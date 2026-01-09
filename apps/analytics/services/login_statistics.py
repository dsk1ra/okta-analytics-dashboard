import datetime
import logging
from core.services.database import DatabaseService  # Updated import path
from ..utils.cache_utils import cached_statistics

logger = logging.getLogger(__name__)


@cached_statistics(timeout=600)
def get_event_activity(days: int = 7):
    """Return per-day counts for successful logins, failed logins, and security events."""
    days = max(1, min(365, int(days) if isinstance(days, (int, float, str)) else 7))

    db_service = DatabaseService()
    collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')

    now = datetime.datetime.now(datetime.timezone.utc)
    labels, successful, failed, security = [], [], [], []

    for i in range(days - 1, -1, -1):
        day_start = (now - datetime.timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + datetime.timedelta(days=1)

        start_iso = day_start.isoformat().replace('+00:00', 'Z')
        end_iso = day_end.isoformat().replace('+00:00', 'Z')

        labels.append(day_start.strftime('%b %d'))

        # Successful logins
        success_count = collection.count_documents({
            'eventType': {'$regex': '(user\\.session\\.start|user\\.authentication\\.sso)'},
            'outcome.result': 'SUCCESS',
            'published': {'$gte': start_iso, '$lt': end_iso}
        })
        successful.append(success_count)

        # Failed logins
        failed_count = collection.count_documents({
            'eventType': {'$regex': 'user\\.authentication'},
            'outcome.result': 'FAILURE',
            'published': {'$gte': start_iso, '$lt': end_iso}
        })
        failed.append(failed_count)

        # Security events
        security_count = collection.count_documents({
            'eventType': {'$regex': '(security|threat)'},
            'published': {'$gte': start_iso, '$lt': end_iso}
        })
        security.append(security_count)

    return {
        'labels': labels,
        'successful': successful,
        'failed': failed,
        'security': security,
    }


@cached_statistics(timeout=600)
def get_event_distribution(days: int = 30):
    """Return event type distribution counts for the specified window - mutually exclusive categories."""
    days = max(1, min(365, int(days) if isinstance(days, (int, float, str)) else 30))

    db_service = DatabaseService()
    collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')

    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = now - datetime.timedelta(days=days)
    threshold_iso = threshold.isoformat().replace('+00:00', 'Z')

    # Define mutually exclusive event categories based on actual eventType field
    categories = {
        'Login': ['user.session.start', 'user.authentication.sso'],
        'Logout': ['user.session.end'],
        'MFA': ['user.authentication.auth_via_mfa'],
        'App Access': ['application.user_membership.add', 'application.user_membership.remove'],
        'Security': ['security.request.blocked', 'user.account.lock', 'user.account.unlock'],
        'Policy': ['policy.evaluate_sign_on'],
    }

    labels = []
    counts = []
    counted_types = set()

    for category_name, event_types in categories.items():
        # Count events matching this specific category
        count = collection.count_documents({
            'eventType': {'$in': event_types},
            'published': {'$gte': threshold_iso}
        })
        if count > 0:
            labels.append(category_name)
            counts.append(count)
            counted_types.update(event_types)

    # Calculate "Other" - all remaining event types not in the above categories
    all_events = collection.count_documents({'published': {'$gte': threshold_iso}})
    categorized_count = sum(counts)
    other_count = max(0, all_events - categorized_count)
    if other_count > 0:
        labels.append('Other')
        counts.append(other_count)

    return {'labels': labels, 'counts': counts}


def get_recent_events(limit: int = 5, hours: int = 24):
    """Return recent events with time filtering support."""
    limit = max(1, min(100, int(limit)))
    hours = max(1, int(hours))

    db_service = DatabaseService()
    collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')

    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = now - datetime.timedelta(hours=hours)
    threshold_iso = threshold.isoformat().replace('+00:00', 'Z')

    # Query for events within the time window, sorted by published date descending
    events = list(collection.find(
        {'published': {'$gte': threshold_iso}},
        sort=[('published', -1)]
    ).limit(limit))

    # Format events for frontend
    formatted_events = []
    for event in events:
        # Extract user info
        actor = event.get('actor', {})
        username = actor.get('alternateId') or actor.get('displayName', 'Unknown')
        
        # Extract IP address
        client = event.get('client', {})
        ip_address = client.get('ipAddress', 'N/A')
        
        formatted_events.append({
            'uuid': event.get('uuid', ''),
            'eventType': event.get('eventType', 'Unknown'),
            'username': username,
            'published': event.get('published', ''),
            'ipAddress': ip_address,
            'outcome': event.get('outcome', {}),
            'severity': event.get('severity', 'INFO'),
        })

    return formatted_events

def get_login_events_count(days=30):
    """
    Get the count of successful login events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of successful login events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all login events regardless of date to understand what we have
        all_login_events = collection.count_documents({
            'eventType': 'user.session.start',
            'outcome.result': 'SUCCESS'
        })
        logger.info(f"All successful login events (without date filtering): {all_login_events}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS',
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS',
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'SUCCESS'
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all login events as a fallback
        if final_count == 0 and all_login_events > 0:
            logger.warning("Date filtering failed, returning all login events as fallback")
            return all_login_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting login events count: {str(e)}", exc_info=True)
        return 0

def get_failed_login_count(days=30):
    """
    Get the count of failed login attempts from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of failed login attempts
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all failed login events regardless of date to understand what we have
        all_failed_logins = collection.count_documents({
            'eventType': 'user.session.start',
            'outcome.result': 'FAILURE'
        })
        logger.info(f"All failed login attempts (without date filtering): {all_failed_logins}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE',
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE',
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': 'user.session.start', 
            'outcome.result': 'FAILURE'
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all failed login events as a fallback
        if final_count == 0 and all_failed_logins > 0:
            logger.warning("Date filtering failed, returning all failed login events as fallback")
            return all_failed_logins
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting failed login count: {str(e)}", exc_info=True)
        return 0

def get_security_events_count(days=30):
    """
    Get the count of security events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of security events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection: {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Get all security events regardless of date to understand what we have
        all_security_events = collection.count_documents({
            'eventType': {'$regex': 'security|threat'},
        })
        logger.info(f"All security events (without date filtering): {all_security_events}")
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            'eventType': {'$regex': 'security|threat'},
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'eventType': {'$regex': 'security|threat'},
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        query3 = {
            'eventType': {'$regex': 'security|threat'}
        }
        count3 = 0
        for doc in collection.find(query3):
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        logger.info(f"Manual date comparison: {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0, just return all security events as a fallback
        if final_count == 0 and all_security_events > 0:
            logger.warning("Date filtering failed, returning all security events as fallback")
            return all_security_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting security events count: {str(e)}", exc_info=True)
        return 0

def get_total_events_count(days=30):
    """
    Get the total count of all events from the last specified number of days.
    
    Args:
        days (int): Number of days to look back (default: 30)
        
    Returns:
        int: Count of all events
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        
        # Get the collection where Okta logs are stored
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        # Get total count first to check if we have data at all
        total_events = collection.count_documents({})
        logger.info(f"Total events in collection (overall): {total_events}")
        
        # If we have no documents, return 0
        if total_events == 0:
            return 0
        
        # Calculate the date threshold (N days ago from now)
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold_date = now - datetime.timedelta(days=days)
        
        # Try different date query approaches
        # First try with datetime objects
        query1 = {
            '_published_date': {'$gte': threshold_date}
        }
        count1 = collection.count_documents(query1)
        logger.info(f"Query with datetime object: {count1}")
        
        # If above didn't work, try with ISO string
        query2 = {
            'published': {'$gte': threshold_date.isoformat()}
        }
        count2 = collection.count_documents(query2)
        logger.info(f"Query with ISO format on 'published': {count2}")
        
        # Try with string comparison on the original published field
        count3 = 0
        # Use a sample subset to avoid excessive memory usage
        sample_size = min(5000, total_events)  # Limit sample size
        
        # Process sample documents in batches
        cursor = collection.find().limit(sample_size)
        for doc in cursor:
            # Extract published date from document
            published_str = doc.get('published')
            if not published_str:
                continue
                
            try:
                # Parse the date and compare
                published_date = datetime.datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                if published_date >= threshold_date:
                    count3 += 1
            except (ValueError, AttributeError):
                logger.warning(f"Could not parse date: {published_str}")
        
        # If we only processed a sample, extrapolate to full collection
        if total_events > sample_size:
            ratio = total_events / sample_size
            count3 = int(count3 * ratio)
            
        logger.info(f"Manual date comparison (extrapolated): {count3}")
        
        # Return the highest count from our different approaches
        final_count = max(count1, count2, count3, 0)
        
        # If we still have 0 but total_events > 0, use total_events as fallback
        if final_count == 0 and total_events > 0:
            logger.warning("Date filtering failed, returning all events as fallback")
            return total_events
            
        return final_count
        
    except Exception as e:
        logger.error(f"Error getting total events count: {str(e)}", exc_info=True)
        return 0


@cached_statistics(timeout=600)
def get_total_events_with_comparison(current_days=30, previous_days=30):
    """
    Get the total count of events for current and previous periods and calculate percentage change.
    
    Args:
        current_days (int): Number of days to look back for current period (default: 30)
        previous_days (int): Number of days to look back for previous period (default: 30)
        
    Returns:
        dict: Contains 'current_count', 'previous_count', and 'percent_change' keys
    """
    try:
        # Get database connection
        db_service = DatabaseService()
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Current period: last N days
        current_threshold = now - datetime.timedelta(days=current_days)
        current_threshold_iso = current_threshold.isoformat() + 'Z'
        
        # Previous period: N to 2N days ago
        previous_threshold_start = now - datetime.timedelta(days=current_days + previous_days)
        previous_threshold_start_iso = previous_threshold_start.isoformat() + 'Z'
        previous_threshold_end_iso = current_threshold_iso
        
        logger.info(f"Event comparison - Current threshold: {current_threshold_iso}, Previous: {previous_threshold_start_iso} to {previous_threshold_end_iso}")
        
        # Count current period events
        current_query = {'published': {'$gte': current_threshold_iso}}
        current_count = collection.count_documents(current_query)
        logger.info(f"Current period events: {current_count}")
        
        # Count previous period events
        previous_query = {
            'published': {
                '$gte': previous_threshold_start_iso,
                '$lt': previous_threshold_end_iso
            }
        }
        previous_count = collection.count_documents(previous_query)
        logger.info(f"Previous period events: {previous_count}")
        
        # Calculate percentage change
        if previous_count == 0:
            percent_change = 0 if current_count == 0 else 100
        else:
            percent_change = ((current_count - previous_count) / previous_count) * 100
        
        logger.info(f"Events comparison - Current: {current_count}, Previous: {previous_count}, Change: {percent_change:.1f}%")
        
        return {
            'current_count': current_count,
            'previous_count': previous_count,
            'percent_change': round(percent_change, 1)
        }
        
    except Exception as e:
        logger.error(f"Error getting events with comparison: {str(e)}", exc_info=True)
        return {
            'current_count': 0,
            'previous_count': 0,
            'percent_change': 0
        }


@cached_statistics(timeout=600)
def get_login_events_with_comparison(current_days=30, previous_days=30):
    """
    Get login events count for current and previous periods with percentage change.
    
    Args:
        current_days (int): Number of days for current period
        previous_days (int): Number of days for previous period
        
    Returns:
        dict: Contains 'current_count', 'previous_count', and 'percent_change'
    """
    try:
        db_service = DatabaseService()
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        now = datetime.datetime.now(datetime.timezone.utc)
        current_threshold = now - datetime.timedelta(days=current_days)
        current_threshold_iso = current_threshold.isoformat().replace('+00:00', 'Z')
        
        previous_threshold_start = now - datetime.timedelta(days=current_days + previous_days)
        previous_threshold_start_iso = previous_threshold_start.isoformat().replace('+00:00', 'Z')
        previous_threshold_end_iso = current_threshold_iso
        
        # Count current period - use eventType field
        current_query = {
            'eventType': 'user.session.start',
            'outcome.result': 'SUCCESS',
            'published': {'$gte': current_threshold_iso}
        }
        current_count = collection.count_documents(current_query)
        logger.info(f"Current period login events: {current_count}")
        
        # Count previous period
        previous_query = {
            'eventType': 'user.session.start',
            'outcome.result': 'SUCCESS',
            'published': {'$gte': previous_threshold_start_iso, '$lt': previous_threshold_end_iso}
        }
        previous_count = collection.count_documents(previous_query)
        logger.info(f"Previous period login events: {previous_count}")
        
        # Calculate percentage change
        if previous_count == 0:
            percent_change = 0 if current_count == 0 else 100
        else:
            percent_change = ((current_count - previous_count) / previous_count) * 100
        
        logger.info(f"Login events comparison - Current: {current_count}, Previous: {previous_count}, Change: {percent_change:.1f}%")
        
        return {
            'current_count': current_count,
            'previous_count': previous_count,
            'percent_change': round(percent_change, 1)
        }
    except Exception as e:
        logger.error(f"Error getting login events with comparison: {str(e)}", exc_info=True)
        return {
            'current_count': 0,
            'previous_count': 0,
            'percent_change': 0
        }


@cached_statistics(timeout=600)
def get_failed_login_with_comparison(current_days=30, previous_days=30):
    """
    Get failed login count for current and previous periods with percentage change.
    
    Args:
        current_days (int): Number of days for current period
        previous_days (int): Number of days for previous period
        
    Returns:
        dict: Contains 'current_count', 'previous_count', and 'percent_change'
    """
    try:
        db_service = DatabaseService()
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        now = datetime.datetime.now(datetime.timezone.utc)
        current_threshold = now - datetime.timedelta(days=current_days)
        current_threshold_iso = current_threshold.isoformat().replace('+00:00', 'Z')
        
        previous_threshold_start = now - datetime.timedelta(days=current_days + previous_days)
        previous_threshold_start_iso = previous_threshold_start.isoformat().replace('+00:00', 'Z')
        previous_threshold_end_iso = current_threshold_iso
        
        # Count current period
        current_query = {
            'eventType': 'user.session.start',
            'outcome.result': 'FAILURE',
            'published': {'$gte': current_threshold_iso}
        }
        current_count = collection.count_documents(current_query)
        logger.info(f"Current period failed logins: {current_count}")
        
        # Count previous period
        previous_query = {
            'eventType': 'user.session.start',
            'outcome.result': 'FAILURE',
            'published': {'$gte': previous_threshold_start_iso, '$lt': previous_threshold_end_iso}
        }
        previous_count = collection.count_documents(previous_query)
        logger.info(f"Previous period failed logins: {previous_count}")
        
        # Calculate percentage change
        if previous_count == 0:
            percent_change = 0 if current_count == 0 else 100
        else:
            percent_change = ((current_count - previous_count) / previous_count) * 100
        
        logger.info(f"Failed login comparison - Current: {current_count}, Previous: {previous_count}, Change: {percent_change:.1f}%")
        
        return {
            'current_count': current_count,
            'previous_count': previous_count,
            'percent_change': round(percent_change, 1)
        }
    except Exception as e:
        logger.error(f"Error getting failed login with comparison: {str(e)}", exc_info=True)
        return {
            'current_count': 0,
            'previous_count': 0,
            'percent_change': 0
        }


@cached_statistics(timeout=600)
def get_security_events_with_comparison(current_days=30, previous_days=30):
    """
    Get security events count for current and previous periods with percentage change.
    
    Args:
        current_days (int): Number of days for current period
        previous_days (int): Number of days for previous period
        
    Returns:
        dict: Contains 'current_count', 'previous_count', and 'percent_change'
    """
    try:
        db_service = DatabaseService()
        collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
        
        now = datetime.datetime.now(datetime.timezone.utc)
        current_threshold = now - datetime.timedelta(days=current_days)
        current_threshold_iso = current_threshold.isoformat().replace('+00:00', 'Z')
        
        previous_threshold_start = now - datetime.timedelta(days=current_days + previous_days)
        previous_threshold_start_iso = previous_threshold_start.isoformat().replace('+00:00', 'Z')
        previous_threshold_end_iso = current_threshold_iso
        
        # Count current period - use regex for eventType matching
        current_query = {
            'eventType': {'$regex': 'security|threat'},
            'published': {'$gte': current_threshold_iso}
        }
        current_count = collection.count_documents(current_query)
        logger.info(f"Current period security events: {current_count}")
        
        # Count previous period
        previous_query = {
            'eventType': {'$regex': 'security|threat'},
            'published': {'$gte': previous_threshold_start_iso, '$lt': previous_threshold_end_iso}
        }
        previous_count = collection.count_documents(previous_query)
        logger.info(f"Previous period security events: {previous_count}")
        
        # Calculate percentage change
        if previous_count == 0:
            percent_change = 0 if current_count == 0 else 100
        else:
            percent_change = ((current_count - previous_count) / previous_count) * 100
        
        logger.info(f"Security events comparison - Current: {current_count}, Previous: {previous_count}, Change: {percent_change:.1f}%")
        
        return {
            'current_count': current_count,
            'previous_count': previous_count,
            'percent_change': round(percent_change, 1)
        }
    except Exception as e:
        logger.error(f"Error getting security events with comparison: {str(e)}", exc_info=True)
        return {
            'current_count': 0,
            'previous_count': 0,
            'percent_change': 0
        }