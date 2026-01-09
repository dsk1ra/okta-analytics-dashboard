import logging
import requests
import base64
import time
import uuid
import re
from urllib.parse import quote
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
from pymongo import MongoClient

from core.services.okta_oauth import OktaOAuthClient
from core.services.database import DatabaseService

logger = logging.getLogger(__name__)

class OktaLogsClient:
    """
    Client for accessing Okta System Logs API with enhanced security features.
    
    This client uses the OAuth 2.0 client credentials flow with:
    1. DPoP (Demonstrating Proof of Possession) for token binding
    2. private_key_jwt for client authentication (more secure than client secret)
    3. Automatic token refresh and proper token lifetime management
    4. Specialized error handling for Logs API permission issues
    5. MongoDB storage for retrieved logs
    """
    
    def __init__(self, use_direct_mongodb=False, debug=False):
        """
        Initialize the Logs API client
        
        Args:
            use_direct_mongodb: If True, use direct MongoDB connection instead of DatabaseService
            debug: Enable debug logging
        """
        self.oauth_client = OktaOAuthClient()
        self.org_url = settings.OKTA_ORG_URL
        self.logs_endpoint = f"{self.org_url}/api/v1/logs"
        self.debug = debug
        
        # Token cache key for this specific client
        self.token_cache_key = "okta_logs_token"
        
        # DPoP nonce cache key
        self.nonce_cache_key = "okta_logs_dpop_nonce"
        
        # MongoDB settings
        self.use_direct_mongodb = use_direct_mongodb
        self.mongo_settings = settings.MONGODB_SETTINGS
        # Choose DB based on DATA_SOURCE (real vs sample)
        if getattr(settings, 'DATA_SOURCE', 'real') == 'sample':
            self.db_name = getattr(settings, 'MONGODB_SAMPLE_DB_NAME', self.mongo_settings.get('db', 'okta_dashboard'))
        else:
            self.db_name = self.mongo_settings.get('db', 'okta_dashboard')
        self.logs_collection_name = 'okta_logs'
        
        # Database service or direct client
        self.db_service = None if use_direct_mongodb else DatabaseService()
        self.mongo_client = None
        
        # Session for connection pooling and performance optimization
        self.session = requests.Session()
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=2,
            pool_block=False
        )
        
        # Mount the adapter for both HTTP and HTTPS
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        logger.info(f"OktaLogsClient initialized with logs endpoint: {self.logs_endpoint}")
    
    def _get_token(self) -> str:
        """
        Get a valid access token, either from cache or by requesting a new one.
        
        Returns:
            Access token string
        """
        # Try to get the token from cache first
        cached_token_data = cache.get(self.token_cache_key)
        
        if cached_token_data:
            # Check if the cached token is still valid (with a 60-second buffer)
            expiry_time = cached_token_data.get('expiry_time', 0)
            if expiry_time > time.time() + 60:
                logger.debug("Using cached Okta API token")
                return cached_token_data.get('access_token')
        
        # No valid cached token, get a new one
        logger.info("Requesting new Okta API token")
        
        # Request token with specific scopes required for logs
        token_data = self.oauth_client.get_client_credentials_token(scopes="okta.logs.read okta.users.read")
        
        access_token = token_data.get('access_token')
        token_type = token_data.get('token_type')
        expires_in = token_data.get('expires_in', 3600)  # Default to 1 hour if not specified
        
        # Calculate absolute expiry time
        expiry_time = time.time() + expires_in
        
        # Cache the token data with absolute expiry time
        cache.set(
            self.token_cache_key,
            {
                'access_token': access_token,
                'token_type': token_type,
                'expiry_time': expiry_time,
                'scope': token_data.get('scope', '')
            },
            # Set cache expiry to match token lifetime (minus a small buffer)
            timeout=expires_in - 60 if expires_in > 60 else expires_in
        )
        
        # Also check for DPoP nonce in response headers and cache it
        dpop_nonce = token_data.get('_dpop_nonce')
        if dpop_nonce:
            cache.set(self.nonce_cache_key, dpop_nonce, timeout=3600)
            logger.debug(f"Cached DPoP nonce: {dpop_nonce}")
        
        return access_token
    
    def _get_mongodb_collection(self):
        """
        Get MongoDB collection for logs - either via DatabaseService or direct connection
        
        Returns:
            MongoDB collection
        """
        try:
            # Use DatabaseService for MongoDB connection (preferred)
            if not self.use_direct_mongodb:
                if self.db_service and self.db_service.is_connected():
                    return self.db_service.get_collection(self.db_name, self.logs_collection_name)
                else:
                    logger.info("DatabaseService not connected, initializing...")
                    self.db_service = DatabaseService()
                    return self.db_service.get_collection(self.db_name, self.logs_collection_name)
            
            # Direct MongoDB connection (legacy/fallback approach)
            else:
                # Get mongodb host from settings
                mongo_host = self.mongo_settings.get('host', 'mongodb://localhost:27017/')
                
                # Create direct connection to MongoDB if needed
                if not self.mongo_client:
                    self.mongo_client = MongoClient(mongo_host)
                    logger.debug(f"Created direct MongoDB connection to {mongo_host}")
                
                # Ensure DB selection honors DATA_SOURCE even on direct connection
                selected_db = self.db_name
                if getattr(settings, 'DATA_SOURCE', 'real') == 'sample':
                    selected_db = getattr(settings, 'MONGODB_SAMPLE_DB_NAME', self.db_name)
                logs_collection = self.mongo_client[selected_db][self.logs_collection_name]
                return logs_collection
                
        except Exception as e:
            logger.error(f"Error getting MongoDB collection: {str(e)}")
            raise
    
    def store_logs_in_mongodb(self, logs_data: List[Dict]) -> int:
        """
        Store logs in MongoDB with proper indexing and error handling
        
        Args:
            logs_data: List of log entries to store
            
        Returns:
            Number of logs successfully inserted
        """
        if not logs_data:
            logger.warning("No logs to store in MongoDB")
            return 0
        
        try:
            # Get MongoDB collection
            logs_collection = self._get_mongodb_collection()
            
            # Create indexes if they don't exist
            try:
                logs_collection.create_index("uuid", unique=True)
                logs_collection.create_index("published")
                logs_collection.create_index("eventType")
                logs_collection.create_index([("actor.id", 1), ("published", -1)])
                logs_collection.create_index([("target.id", 1), ("published", -1)])
                if self.debug:
                    logger.debug("Successfully created MongoDB indexes for logs collection")
            except Exception as e:
                if self.debug:
                    logger.debug(f"Note about indexes: {str(e)}")
            
            # Process the logs for storage
            # Add import timestamp
            for log in logs_data:
                log['_imported_at'] = datetime.utcnow().isoformat()
                
                # Add MongoDB-specific fields for efficient querying
                if 'published' in log and isinstance(log['published'], str):
                    try:
                        # Store the published date as ISODate for MongoDB
                        published_date = datetime.fromisoformat(log['published'].replace('Z', '+00:00'))
                        log['_published_date'] = published_date.isoformat()
                    except Exception as date_error:
                        if self.debug:
                            logger.debug(f"Error parsing published date: {date_error}")
            
            inserted_count = 0
            try:
                # Use bulk insert with unordered option to continue on duplicate key errors
                result = logs_collection.insert_many(logs_data, ordered=False)
                inserted_count = len(result.inserted_ids)
                logger.info(f"Successfully stored {inserted_count} logs in MongoDB")
            except Exception as e:
                if "E11000 duplicate key error" in str(e):
                    # Try to extract count from the error message
                    match = re.search(r'Inserted (\d+) document', str(e))
                    if match:
                        inserted_count = int(match.group(1))
                        logger.info(f"Partially inserted {inserted_count} logs, some were already in MongoDB (duplicate keys)")
                    else:
                        logger.info("Some logs were already in MongoDB (duplicate keys)")
                else:
                    logger.error(f"Error during MongoDB insertion: {str(e)}")
                    raise
            
            return inserted_count
                
        except Exception as e:
            logger.error(f"Error with MongoDB integration: {str(e)}")
            return 0
    
    def calculate_start_time(self, days: int = 0, hours: int = 0, minutes: int = 15) -> datetime:
        """
        Calculate the start time based on provided days, hours, and minutes
        
        Args:
            days: Number of days to go back
            hours: Number of hours to go back
            minutes: Number of minutes to go back
            
        Returns:
            Start time as datetime object
        """
        # Calculate total minutes
        total_minutes = days * 24 * 60 + hours * 60 + minutes
        if total_minutes <= 0:
            total_minutes = 15  # Default to 15 minutes
        
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=total_minutes)
        
        logger.info(f"Calculated time range: {total_minutes} minutes ({days} days, {hours} hours, {minutes} minutes)")
        return start_time
    
    def fetch_logs(self, 
                  since: Optional[datetime] = None, 
                  days: int = 0, 
                  hours: int = 0, 
                  minutes: int = 15,
                  limit: int = 100, 
                  filter_query: Optional[str] = None, 
                  max_pages: int = 10, 
                  store_in_mongodb: bool = True) -> List[Dict]:
        """
        Fetch logs from Okta System Log API with pagination
        
        Args:
            since: Start time as datetime object (if provided, days/hours/minutes are ignored)
            days: Number of days to go back (if since is not provided)
            hours: Number of hours to go back (if since is not provided)
            minutes: Number of minutes to go back (if since is not provided)
            limit: Maximum number of logs to fetch per request (max 1000)
            filter_query: Filter query for Okta logs (e.g. "eventType eq \"user.session.start\"")
            max_pages: Maximum number of pages to fetch (0 for unlimited)
            store_in_mongodb: Whether to store fetched logs in MongoDB
            
        Returns:
            List of log entries
        """
        # Calculate the start time if not provided
        if since is None:
            start_time = self.calculate_start_time(days, hours, minutes)
        else:
            start_time = since
            
        # Format the start time for Okta's since parameter (ISO 8601 with exactly 3 decimal places)
        since_iso = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        logger.info(f"Fetching Okta logs since {since_iso}")
        
        # Get access token
        access_token = self._get_token()
        if not access_token:
            logger.error("Could not obtain access token for Okta Logs API")
            return []
        
        # Build query parameters
        query_params = {}
        
        # Add limit parameter (ensure it doesn't exceed Okta's maximum)
        query_params["limit"] = min(limit, 1000)
        
        # Add since parameter (recommended by Okta API docs)
        query_params["since"] = since_iso
        
        # Add filter if specified
        if filter_query:
            query_params["filter"] = filter_query
        
        # Get cached nonce if available
        api_nonce = cache.get(self.nonce_cache_key)
        
        # Track pagination
        page_count = 0
        total_logs = 0
        has_more_pages = True
        next_url = None
        all_logs = []  # Collect all logs for later insertion
        
        # Continue fetching pages until we've reached the max or there are no more
        while has_more_pages and (max_pages == 0 or page_count < max_pages):
            page_count += 1
            logger.info(f"Fetching page {page_count} of logs...")
            
            # Use the next URL from Link header if we have one, otherwise use the base URL with params
            url_to_fetch = next_url if next_url else self.logs_endpoint
            
            # For the first page, we need to add query params
            if page_count == 1:
                # Build the URL with query parameters
                params_list = []
                
                for key, value in query_params.items():
                    encoded_value = quote(str(value))
                    params_list.append(f"{key}={encoded_value}")
                
                params_string = "&".join(params_list)
                url_with_params = f"{url_to_fetch}?{params_string}"
                
                if self.debug:
                    logger.debug(f"First page URL: {url_with_params}")
            else:
                # Use the next URL directly
                url_with_params = url_to_fetch
                if self.debug:
                    logger.debug(f"Next page URL: {url_with_params}")
            
            # Get headers for the API request. Use DPoP since token is DPoP-bound.
            logs_headers = self.oauth_client.create_api_headers(
                access_token=access_token,
                method="GET",
                url=self.logs_endpoint,
                nonce=api_nonce,
                use_dpop=True
            )
            
            try:
                # Make the request - use proper approach based on page
                if page_count == 1:
                    # For first page, use query parameters
                    logs_response = self.session.get(
                        url_with_params,
                        headers=logs_headers,
                        timeout=30
                    )
                else:
                    # For pagination, just use the next URL directly
                    logs_response = self.session.get(
                        url_with_params,
                        headers=logs_headers,
                        timeout=30
                    )
                
                logger.debug(f"Logs API status for page {page_count}: {logs_response.status_code}")
                
                if logs_response.status_code == 200:
                    # Extract logs from response
                    page_logs = logs_response.json()
                    page_log_count = len(page_logs)
                    total_logs += page_log_count
                    
                    logger.info(f"Successfully retrieved {page_log_count} logs on page {page_count}")
                    
                    # Add logs to our collection
                    all_logs.extend(page_logs)
                    
                    # Check if there are more pages via Link header
                    link_header = logs_response.headers.get('Link', '')
                    if self.debug:
                        logger.debug(f"Link header: {link_header}")
                    
                    # Extract next URL if there is one
                    next_url = None
                    if link_header:
                        # Parse the Link header to find the "next" link
                        links = link_header.split(',')
                        for link in links:
                            if 'rel="next"' in link:
                                url_match = re.search(r'<([^>]+)>', link)
                                if url_match:
                                    next_url = url_match.group(1)
                                    if self.debug:
                                        logger.debug(f"Found next URL: {next_url}")
                                    break
                    
                    # Set has_more_pages based on whether we found a next URL
                    has_more_pages = next_url is not None
                    
                    # If this page had fewer logs than the limit, we're done
                    if page_log_count < limit:
                        has_more_pages = False
                        if self.debug:
                            logger.debug("Fewer logs than limit returned, no more pages to fetch")
                    
                    # Update the nonce for the next request if needed
                    if "DPoP-Nonce" in logs_response.headers:
                        api_nonce = logs_response.headers.get("DPoP-Nonce")
                        cache.set(self.nonce_cache_key, api_nonce, timeout=3600)
                        if self.debug:
                            logger.debug(f"Got new nonce for next page: {api_nonce}")
                else:
                    logger.error(f"Failed to access logs API on page {page_count}. Status: {logs_response.status_code}")
                    retried_with_nonce = False
                    try:
                        error_details = {}
                        try:
                            error_details = logs_response.json()
                            logger.error(f"Error details: {error_details}")
                        except Exception:
                            logger.error(f"Response content: {logs_response.text[:200]}")

                        # If server requires DPoP nonce, retry once with provided nonce
                        if logs_response.status_code in (400, 401):
                            new_nonce = logs_response.headers.get("DPoP-Nonce")
                            if not new_nonce:
                                www_auth = logs_response.headers.get("WWW-Authenticate", "")
                                m = re.search(r'nonce="([^\"]+)"', www_auth)
                                if m:
                                    new_nonce = m.group(1)
                            if new_nonce:
                                cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
                                api_nonce = new_nonce
                                logger.info(f"Retrying logs request with DPoP nonce: {new_nonce}")
                                logs_headers = self.oauth_client.create_api_headers(
                                    access_token=access_token,
                                    method="GET",
                                    url=self.logs_endpoint,
                                    nonce=api_nonce,
                                    use_dpop=True
                                )
                                logs_response = self.session.get(
                                    url_with_params,
                                    headers=logs_headers,
                                    timeout=30
                                )
                                retried_with_nonce = True
                    finally:
                        # If retry succeeded, process as success
                        if retried_with_nonce and logs_response.status_code == 200:
                            page_logs = logs_response.json()
                            page_log_count = len(page_logs)
                            total_logs += page_log_count
                            logger.info(f"Successfully retrieved {page_log_count} logs on page {page_count} (after nonce retry)")
                            all_logs.extend(page_logs)
                            link_header = logs_response.headers.get('Link', '')
                            if self.debug:
                                logger.debug(f"Link header: {link_header}")
                            next_url = None
                            if link_header:
                                links = link_header.split(',')
                                for link in links:
                                    if 'rel="next"' in link:
                                        url_match = re.search(r'<([^>]+)>', link)
                                        if url_match:
                                            next_url = url_match.group(1)
                                            if self.debug:
                                                logger.debug(f"Found next URL: {next_url}")
                                            break
                            has_more_pages = next_url is not None
                            if page_log_count < limit:
                                has_more_pages = False
                                if self.debug:
                                    logger.debug("Fewer logs than limit returned, no more pages to fetch")
                            if "DPoP-Nonce" in logs_response.headers:
                                api_nonce = logs_response.headers.get("DPoP-Nonce")
                                cache.set(self.nonce_cache_key, api_nonce, timeout=3600)
                                if self.debug:
                                    logger.debug(f"Got new nonce for next page: {api_nonce}")
                        else:
                            # Check if we need to refresh the token
                            if logs_response.status_code == 401:
                                cache.delete(self.token_cache_key)
                                if "DPoP-Nonce" in logs_response.headers:
                                    new_nonce = logs_response.headers.get("DPoP-Nonce")
                                    cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
                                    logger.info(f"Got new nonce from error response: {new_nonce}")
                            has_more_pages = False
                    
                    # Check if we need to refresh the token
                    if logs_response.status_code == 401:
                        # Clear token from cache to force refresh
                        cache.delete(self.token_cache_key)
                        
                        # Get a new nonce if available
                        if "DPoP-Nonce" in logs_response.headers:
                            new_nonce = logs_response.headers.get("DPoP-Nonce")
                            cache.set(self.nonce_cache_key, new_nonce, timeout=3600)
                            logger.info(f"Got new nonce from error response: {new_nonce}")
                    
                    # Stop pagination if we encounter an error
                    has_more_pages = False
            except Exception as e:
                logger.error(f"Error accessing logs API on page {page_count}: {str(e)}")
                has_more_pages = False
        
        # Summarize the results
        logger.info(f"Fetched a total of {total_logs} logs across {page_count} pages")
        
        # Store logs in MongoDB if requested
        if store_in_mongodb and all_logs:
            logger.info("Storing logs in MongoDB...")
            inserted_count = self.store_logs_in_mongodb(all_logs)
            logger.info(f"Operation complete: Stored {inserted_count} of {total_logs} logs in MongoDB")
        
        return all_logs
    
    def get_logs_since(self, 
                      iso_timestamp: str, 
                      limit: int = 100, 
                      filter_query: Optional[str] = None, 
                      max_pages: int = 10,
                      store_in_mongodb: bool = True) -> List[Dict]:
        """
        Get logs since a specific ISO 8601 timestamp
        
        Args:
            iso_timestamp: ISO 8601 timestamp string (e.g. "2025-05-01T00:00:00.000Z")
            limit: Maximum number of logs to fetch per request
            filter_query: Filter query for Okta logs
            max_pages: Maximum number of pages to fetch
            store_in_mongodb: Whether to store fetched logs in MongoDB
            
        Returns:
            List of log entries
        """
        try:
            # Parse the provided ISO8601 timestamp
            start_time = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
            logger.info(f"Fetching logs since: {iso_timestamp}")
            
            # Use the main fetch_logs method with the parsed timestamp
            return self.fetch_logs(
                since=start_time,
                limit=limit,
                filter_query=filter_query,
                max_pages=max_pages,
                store_in_mongodb=store_in_mongodb
            )
        except Exception as e:
            logger.error(f"Error parsing ISO timestamp: {e}")
            # Fall back to default time range
            logger.warning("Using default time range instead")
            return self.fetch_logs(
                days=0, 
                hours=0, 
                minutes=15, 
                limit=limit,
                filter_query=filter_query,
                max_pages=max_pages,
                store_in_mongodb=store_in_mongodb
            )
    
    def get_logs_by_timeframe(self, 
                             days: int = 0, 
                             hours: int = 0, 
                             minutes: int = 15,
                             limit: int = 100, 
                             filter_query: Optional[str] = None, 
                             max_pages: int = 10,
                             store_in_mongodb: bool = True) -> List[Dict]:
        """
        Get logs for a specific timeframe (days, hours, minutes ago)
        
        Args:
            days: Number of days to go back
            hours: Number of hours to go back
            minutes: Number of minutes to go back
            limit: Maximum number of logs to fetch per request
            filter_query: Filter query for Okta logs
            max_pages: Maximum number of pages to fetch
            store_in_mongodb: Whether to store fetched logs in MongoDB
            
        Returns:
            List of log entries
        """
        return self.fetch_logs(
            days=days,
            hours=hours,
            minutes=minutes,
            limit=limit,
            filter_query=filter_query,
            max_pages=max_pages,
            store_in_mongodb=store_in_mongodb
        )
    
    def close(self):
        """Close any open connections"""
        if self.mongo_client:
            self.mongo_client.close()
            logger.debug("Direct MongoDB connection closed")
        
        if self.session:
            self.session.close()
            logger.debug("HTTP session closed")