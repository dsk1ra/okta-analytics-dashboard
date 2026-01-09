import logging
from django_q.models import Schedule
from django_q.tasks import schedule, async_task
import sys
import os
import json
from datetime import datetime, timedelta
from django.conf import settings
from core.services.database import DatabaseService  # Updated import path

logger = logging.getLogger(__name__)

def get_last_okta_log_timestamp():
    """
    Get the timestamp of the most recently retrieved Okta log.
    
    Returns:
        str: ISO8601 formatted timestamp of the last fetched log,
             or a timestamp from 15 minutes ago if no record exists
    """
    try:
        # Try to connect to MongoDB and get the most recent log
        db_service = DatabaseService()
        if db_service.is_connected():
            client = db_service.get_client()
            
            # Get database name from settings
            db_name = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
            collection = client[db_name]['okta_logs']
            
            # Find the most recent log by published date (descending order)
            most_recent_log = collection.find_one(
                {}, 
                sort=[("published", -1)]
            )
            
            if (most_recent_log and 'published' in most_recent_log):
                timestamp = most_recent_log['published']
                logger.info(f"Found most recent log timestamp: {timestamp}")
                return timestamp
    except Exception as e:
        logger.error(f"Error retrieving last log timestamp: {str(e)}")
    
    # Default: return timestamp from 15 minutes ago
    default_time = datetime.utcnow() - timedelta(minutes=15)
    default_timestamp = default_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    logger.info(f"Using default timestamp from 15 minutes ago: {default_timestamp}")
    return default_timestamp

def register_scheduled_tasks():
    """
    Register scheduled tasks for the application
    """
    logger.info("Registering scheduled tasks...")
    
    # Delete ALL existing schedules to clean up old/broken ones
    Schedule.objects.all().delete()
    logger.info("Cleaned up all existing scheduled tasks")
    
    # Start the self-perpetuating Okta logs fetch task chain
    start_okta_logs_chain()
    
    logger.info("Successfully initiated Okta logs fetch chain")
    
    # Run an immediate fetch of Okta logs at startup
    if 'runserver' in sys.argv or 'uvicorn' in sys.argv:
        initial_fetch_logs()

def fetch_okta_logs_with_dpop():
    """
    Fetch Okta logs using DPoP authentication with continuous, gap-free collection.
    Each run uses the timestamp of the most recently retrieved log as the --since parameter.
    """
    try:
        # Get the timestamp of the most recent log
        since_timestamp = get_last_okta_log_timestamp()
        
        # Run the fetch_okta_logs_dpop command
        async_task(
            'django.core.management.call_command',
            'fetch_okta_logs_dpop',
            '--since', since_timestamp,
            '--max-pages', '0',    # Unlimited pages
            '--limit', '1000',     # Maximum logs per request
            hook='apps.analytics.scheduler.dpop_log_fetch_callback'
        )
        logger.info(f"Scheduled Okta logs fetch with DPoP (since {since_timestamp})")
    except Exception as e:
        logger.error(f"Error scheduling Okta logs fetch with DPoP: {str(e)}")

def self_perpetuating_okta_logs_fetch():
    """
    Fetch Okta logs and then schedule the next execution.
    This function creates a chain of executions where each run schedules the next one.
    """
    task_id = None
    try:
        # Get the timestamp of the most recent log
        since_timestamp = get_last_okta_log_timestamp()
        logger.info(f"Starting self-perpetuating Okta logs fetch (since {since_timestamp})")
        
        # Run the fetch_okta_logs_dpop command and get the task ID
        task_result = async_task(
            'django.core.management.call_command',
            'fetch_okta_logs_dpop',
            '--since', since_timestamp,
            '--max-pages', '0',    # Unlimited pages
            '--limit', '1000',     # Maximum logs per request
            hook='apps.analytics.scheduler.self_perpetuating_callback'
        )
        
        if task_result:
            task_id = str(task_result) 
            logger.info(f"Scheduled Okta logs fetch with DPoP (Task ID: {task_id})")
        else:
            logger.error("Failed to get task ID for Okta logs fetch")
            # Schedule the next execution anyway to maintain the chain
            schedule_next_execution()
            
    except Exception as e:
        logger.error(f"Error in self-perpetuating Okta logs fetch: {str(e)}")
        # Even on error, schedule the next execution to maintain the chain
        schedule_next_execution()
    
    return task_id

def self_perpetuating_callback(task):
    """
    Callback for the self-perpetuating task. This function is called when the
    Okta logs fetch is completed, and schedules the next execution.
    """
    if task.success:
        logger.info(f"Okta logs fetch completed successfully (Task ID: {task.id})")
    else:
        logger.error(f"Okta logs fetch failed (Task ID: {task.id}): {task.result}")
    
    # Schedule the next execution
    schedule_next_execution()

def schedule_next_execution(delay_seconds=60):
    """
    Schedule the next execution of the self-perpetuating Okta logs fetch task.
    
    Args:
        delay_seconds: Number of seconds to wait before the next execution (default: 60)
    """
    try:
        # Calculate the next run time with timezone awareness
        from django.utils import timezone
        import uuid
        next_run = timezone.now() + timedelta(seconds=delay_seconds)
        
        # Create a unique name for this scheduled task
        task_name = f'okta_logs_dpop_fetch_{uuid.uuid4().hex[:8]}'
        
        # Schedule the next execution as a one-time task
        schedule(
            'apps.analytics.scheduler.self_perpetuating_okta_logs_fetch',
            name=task_name,
            schedule_type='O',  # 'O' for 'ONCE'
            next_run=next_run
        )
        logger.info(f"Scheduled next Okta logs fetch in {delay_seconds} seconds (at {next_run.isoformat()}, name: {task_name})")
    except Exception as e:
        logger.error(f"Failed to schedule next Okta logs fetch: {str(e)}")
        # In case of failure, try again with a longer delay
        try:
            from django.utils import timezone
            import uuid
            next_run = timezone.now() + timedelta(seconds=delay_seconds * 2)
            task_name = f'okta_logs_dpop_fetch_retry_{uuid.uuid4().hex[:8]}'
            schedule(
                'apps.analytics.scheduler.self_perpetuating_okta_logs_fetch',
                name=task_name,
                schedule_type='O',  # 'O' for 'ONCE'
                next_run=next_run
            )
            logger.info(f"Rescheduled next Okta logs fetch with extended delay ({delay_seconds * 2} seconds, name: {task_name})")
        except Exception as retry_error:
            logger.error(f"Failed to reschedule next Okta logs fetch: {str(retry_error)}")

def start_okta_logs_chain():
    """
    Start the chain of self-perpetuating Okta logs fetch tasks.
    This function initiates the first task in the chain.
    """
    try:
        # Remove any existing schedules for this task
        Schedule.objects.filter(func='apps.analytics.scheduler.self_perpetuating_okta_logs_fetch').delete()
        
        # Import timezone and uuid
        from django.utils import timezone
        import uuid
        
        # Create a unique name for the initial scheduled task
        task_name = f'okta_logs_dpop_fetch_initial_{uuid.uuid4().hex[:8]}'
        
        # Schedule the first task to run immediately
        task = schedule(
            'apps.analytics.scheduler.self_perpetuating_okta_logs_fetch',
            name=task_name,
            schedule_type='O',  # 'O' for 'ONCE'
            next_run=timezone.now()  # Run immediately
        )
        
        if task:
            logger.info(f"Started Okta logs fetch chain (Initial task: {task_name})")
            return task.id
        else:
            logger.error("Failed to schedule initial Okta logs fetch task")
            return None
    except Exception as e:
        logger.error(f"Failed to start Okta logs fetch chain: {str(e)}")
        return None

def dpop_log_fetch_callback(task):
    """
    Callback function for the async DPoP log fetch task
    """
    if task.success:
        logger.info("Okta logs fetch with DPoP completed successfully")
    else:
        logger.error(f"Okta logs fetch with DPoP failed: {task.result}")

def initial_fetch_logs():
    """
    Perform an initial fetch of Okta logs at server startup.
    This ensures we have fresh data immediately without waiting for the schedule.
    """
    try:
        # Make sure MongoDB is connected first
        db_service = DatabaseService()
        if not db_service.is_connected():
            logger.warning("MongoDB connection failed during startup, skipping initial log fetch")
            return
            
        logger.info("Performing initial Okta logs fetch at startup...")
        
        # Do an initial fetch using DPoP authentication
        fetch_okta_logs_with_dpop()
        logger.info("Initial fetch of Okta logs with DPoP authentication scheduled")
    except Exception as e:
        logger.error(f"Error during initial Okta logs fetch: {str(e)}")

def log_fetch_callback(task):
    """
    Callback function for the async log fetch task
    """
    if task.success:
        logger.info("Initial Okta logs fetch completed successfully")
    else:
        logger.error(f"Initial Okta logs fetch failed: {task.result}")

def setup_scheduled_tasks(sender, **kwargs):
    """
    Signal handler for post_migrate signal.
    This ensures database operations only happen after the app is fully initialized 
    and migrations are complete.
    
    Args:
        sender: The sender of the signal
        **kwargs: Additional arguments passed by the signal
    """
    # Only register tasks when running the main server process, not during tests or other commands
    import sys
    if 'runserver' in sys.argv or 'uvicorn' in sys.argv:
        try:
            # Ensure MongoDB is connected
            db_service = DatabaseService()
            if db_service.is_connected():
                logger.info("MongoDB connection verified during server startup")
            else:
                logger.warning("MongoDB connection check failed during startup")
                
            register_scheduled_tasks()
        except Exception as e:
            logger.error(f"Failed to register scheduled tasks: {str(e)}")