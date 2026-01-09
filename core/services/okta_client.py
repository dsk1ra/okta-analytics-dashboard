import logging
import requests
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class OktaApiClient:
    """
    Client for interacting with the Okta API.

    This client provides methods to fetch user logs and security events
    from the Okta API with proper authentication and error handling.
    
    Supports both OAuth 2.0 tokens (preferred for zero-trust) and API tokens.
    """

    def __init__(self, api_token: Optional[str] = None, org_url: Optional[str] = None, oauth_token: Optional[str] = None):
        """
        Initialize the Okta API client.

        Args:
            api_token: The Okta API token for authentication (legacy approach)
            org_url: The Okta organization URL
            oauth_token: OAuth 2.0 access token (preferred for zero-trust model)
        """
        # Prioritize provided parameters, then environment variables, then settings
        self.api_token = api_token or os.environ.get('OKTA_API_TOKEN', settings.OKTA_API_TOKEN)
        self.org_url = org_url or os.environ.get('OKTA_ORG_URL', settings.OKTA_ORG_URL)
        self.oauth_token = oauth_token
        self.base_url = f"{self.org_url}/api/v1"
        
        # Trace client configuration at debug level
        logger.debug(f"OktaApiClient initialized with URL: {self.org_url}")
        
        # Use OAuth token when available (preferred), otherwise fall back to API token
        if self.oauth_token:
            logger.info("Using OAuth token for Okta API authentication (preferred)")
            self.headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.oauth_token}"
            }
        else:
            logger.info("Using API token for Okta API authentication")
            self.headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"SSWS {self.api_token}"
            }

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict]:
        """
        Make a GET request to the Okta API with zero-trust principles.
        
        In a zero-trust model, we don't assume the connection or token is still valid,
        so we handle token expiry and other authentication issues explicitly.

        Args:
            endpoint: API endpoint to call
            params: Optional query parameters

        Returns:
            List of response objects

        Raises:
            Exception: If the API request fails
        """
        url = f"{self.base_url}/{endpoint}"
        all_results = []

        try:
            response = requests.get(url, headers=self.headers, params=params)
            
            # Handle authentication errors specifically to provide better feedback
            if response.status_code == 401:
                if self.oauth_token:
                    logger.error("OAuth token rejected or expired")
                    raise Exception("OAuth token unauthorized - token may have expired or been revoked")
                else:
                    logger.error("API token rejected")
                    raise Exception("API token unauthorized - token may be invalid or revoked")
            
            # Handle other error statuses
            response.raise_for_status()

            # Add results from current page
            results = response.json()
            if isinstance(results, list):
                all_results.extend(results)
            else:
                # Some endpoints return a single object instead of a list
                return [results]

            # Check for pagination
            while "next" in response.links:
                next_url = response.links["next"]["url"]
                response = requests.get(next_url, headers=self.headers)
                # Re-check authentication for each request (zero-trust approach)
                if response.status_code == 401:
                    logger.error("Authentication token became invalid during pagination")
                    raise Exception("Authentication failed during paginated request - token may have expired")
                response.raise_for_status()
                all_results.extend(response.json())

            return all_results

        except requests.exceptions.RequestException as e:
            logger.error(f"Error making request to Okta API: {e}")
            raise Exception(f"Failed to retrieve data from Okta API: {str(e)}")
    
    def get_user_logs(self,
                      user_id: Optional[str] = None,
                      since: Optional[Union[datetime, str]] = None,
                      until: Optional[Union[datetime, str]] = None,
                      filter_query: Optional[str] = None,
                      limit: int = 100,
                      cache_timeout: int = 300) -> List[Dict]:
        """
        Fetch user logs from the Okta System Log API.

        Args:
            user_id: Optional Okta user ID to filter logs
            since: Start time for logs (datetime or ISO-8601 string)
            until: End time for logs (datetime or ISO-8601 string)
            filter_query: Additional filter expression (https://developer.okta.com/docs/reference/api/system-log/#expression-filter)
            limit: Maximum number of logs to return
            cache_timeout: Cache timeout in seconds (default: 5 minutes)

        Returns:
            List of user log events
        """
        # Create cache key based on parameters
        cache_key = f"okta_user_logs_{user_id}_{since}_{until}_{filter_query}_{limit}"
        cached_logs = cache.get(cache_key)
        if cached_logs:
            return cached_logs

        params = {"limit": limit}

        if since:
            if isinstance(since, datetime):
                since = since.isoformat()
            params["since"] = since

        if until:
            if isinstance(until, datetime):
                until = until.isoformat()
            params["until"] = until

        # Build filter query
        filters = []
        if user_id:
            filters.append(f'target.id eq "{user_id}"')

        if filter_query:
            filters.append(f"({filter_query})")

        if filters:
            params["filter"] = " and ".join(filters)

        logs = self._make_request("logs", params)

        # Cache the results
        cache.set(cache_key, logs, cache_timeout)

        return logs

    def get_security_events(self,
                            since: Optional[Union[datetime, str]] = None,
                            until: Optional[Union[datetime, str]] = None,
                            event_types: Optional[List[str]] = None,
                            ip_address: Optional[str] = None,
                            user_id: Optional[str] = None,
                            limit: int = 100,
                            cache_timeout: int = 300) -> List[Dict]:
        """
        Fetch security events from the Okta System Log API.

        Args:
            since: Start time for events (datetime or ISO-8601 string)
            until: End time for events (datetime or ISO-8601 string)
            event_types: List of specific security event types to filter
            ip_address: Filter by specific IP address
            user_id: Filter by specific user ID
            limit: Maximum number of events to return
            cache_timeout: Cache timeout in seconds (default: 5 minutes)

        Returns:
            List of security events
        """
        # Common security event types in Okta
        security_event_types = event_types or [
            "security.request.blocked",
            "user.session.start",
            "user.session.end",
            "system.api_token.access",
            "user.authentication.sso",
            "user.authentication.auth_via_mfa",
            "security.threat.detected",
            "user.account.lock",
            "user.account.unlock",
            "user.mfa.factor.update",
            "user.mfa.factor.reset",
            "user.authentication.failure",
            "security.risk.detected"
        ]

        # Create cache key based on parameters
        cache_key = f"okta_security_events_{since}_{until}_{'-'.join(security_event_types)}_{ip_address}_{user_id}_{limit}"
        cached_events = cache.get(cache_key)
        if cached_events:
            return cached_events

        # Build filter query for security events
        filters = []

        # Add event type filter
        event_type_filter = " or ".join([f'eventType eq "{event_type}"' for event_type in security_event_types])
        filters.append(f"({event_type_filter})")

        # Add IP address filter if provided
        if ip_address:
            filters.append(f'client.ipAddress eq "{ip_address}"')

        # Add user ID filter if provided
        if user_id:
            filters.append(f'actor.id eq "{user_id}"')

        filter_query = " and ".join(filters)

        # Get the events using the user logs endpoint with appropriate filters
        events = self.get_user_logs(
            since=since,
            until=until,
            filter_query=filter_query,
            limit=limit,
            cache_timeout=0  # Don't cache within the method as we'll cache here
        )

        # Cache the results
        cache.set(cache_key, events, cache_timeout)

        return events

    def get_failed_login_attempts(self,
                                  user_id: Optional[str] = None,
                                  since: Optional[Union[datetime, str]] = None,
                                  limit: int = 100) -> List[Dict]:
        """
        Get failed login attempts for a user or all users.

        Args:
            user_id: Optional Okta user ID to filter logs
            since: Start time for logs (defaults to 7 days ago)
            limit: Maximum number of logs to return

        Returns:
            List of failed login attempt events
        """
        if not since:
            since = datetime.now() - timedelta(days=7)

        filter_query = 'eventType eq "user.authentication.failure"'

        return self.get_user_logs(
            user_id=user_id,
            since=since,
            filter_query=filter_query,
            limit=limit
        )

    def get_user_details(self, user_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific user.

        Args:
            user_id: Okta user ID

        Returns:
            User information dictionary
        """
        return self._make_request(f"users/{user_id}")[0]

    def get_user_groups(self, user_id: str) -> List[Dict]:
        """
        Get groups that a user belongs to.

        Args:
            user_id: Okta user ID

        Returns:
            List of group objects
        """
        return self._make_request(f"users/{user_id}/groups")