"""
Sample data generator for testing and development without real Okta data.
"""
import random
import datetime
from typing import List, Dict, Any


class SampleDataService:
    """Generate sample Okta-like data for testing and development."""
    
    SAMPLE_USERS = [
        "john.doe@example.com", "jane.smith@example.com", "bob.johnson@example.com",
        "alice.williams@example.com", "charlie.brown@example.com", "diana.davis@example.com",
        "edward.miller@example.com", "fiona.wilson@example.com", "george.moore@example.com",
        "hannah.taylor@example.com"
    ]
    
    SAMPLE_APPS = [
        "Salesforce", "Slack", "Google Workspace", "Microsoft 365", "Zoom",
        "GitHub", "Jira", "Confluence", "AWS Console", "Azure Portal"
    ]
    
    SAMPLE_LOCATIONS = [
        {"city": "New York", "state": "NY", "country": "US", "lat": 40.7128, "lon": -74.0060},
        {"city": "Los Angeles", "state": "CA", "country": "US", "lat": 34.0522, "lon": -118.2437},
        {"city": "Chicago", "state": "IL", "country": "US", "lat": 41.8781, "lon": -87.6298},
        {"city": "London", "state": "", "country": "GB", "lat": 51.5074, "lon": -0.1278},
        {"city": "Tokyo", "state": "", "country": "JP", "lat": 35.6762, "lon": 139.6503},
        {"city": "Sydney", "state": "NSW", "country": "AU", "lat": -33.8688, "lon": 151.2093},
    ]
    
    EVENT_TYPES = [
        "user.session.start", "user.authentication.auth_via_mfa", 
        "application.user_membership.add", "user.session.end",
        "user.authentication.sso", "policy.evaluate_sign_on"
    ]
    
    DEVICES = ["Desktop", "Mobile", "Tablet"]
    BROWSERS = ["Chrome", "Firefox", "Safari", "Edge"]
    OS_TYPES = ["Windows", "macOS", "Linux", "iOS", "Android"]
    
    AUTH_METHODS = ["Password", "SMS", "Email", "Google Authenticator", "Okta Verify", "Password/IDP"]
    
    @classmethod
    def generate_events(cls, count: int = 100, days: int = 30) -> List[Dict[str, Any]]:
        """Generate sample Okta log events."""
        events = []
        now = datetime.datetime.now(datetime.timezone.utc)
        
        for _ in range(count):
            # Random time within the past N days
            hours_ago = random.randint(0, days * 24)
            event_time = now - datetime.timedelta(hours=hours_ago)
            
            location = random.choice(cls.SAMPLE_LOCATIONS)
            user_email = random.choice(cls.SAMPLE_USERS)
            
            # Determine success outcome (90% success rate)
            outcome = "SUCCESS" if random.random() < 0.9 else "FAILURE"
            
            event = {
                "uuid": f"sample-{random.randint(100000, 999999)}",
                "published": event_time.isoformat().replace('+00:00', 'Z'),
                "eventType": random.choice(cls.EVENT_TYPES),
                "displayMessage": f"User {user_email} authentication",
                "outcome": {
                    "result": outcome
                },
                "actor": {
                    "id": f"user-{random.randint(1000, 9999)}",
                    "type": "User",
                    "alternateId": user_email,
                    "displayName": user_email.split('@')[0].replace('.', ' ').title()
                },
                "client": {
                    "userAgent": {
                        "rawUserAgent": f"{random.choice(cls.BROWSERS)}/100.0",
                        "os": random.choice(cls.OS_TYPES),
                        "browser": random.choice(cls.BROWSERS)
                    },
                    "device": random.choice(cls.DEVICES),
                    "geographicalContext": {
                        "city": location["city"],
                        "state": location["state"],
                        "country": location["country"],
                        "geolocation": {
                            "lat": location["lat"],
                            "lon": location["lon"]
                        }
                    }
                },
                "target": [
                    {
                        "id": f"app-{random.randint(1000, 9999)}",
                        "type": "AppInstance",
                        "alternateId": random.choice(cls.SAMPLE_APPS),
                        "displayName": random.choice(cls.SAMPLE_APPS)
                    }
                ],
                "authenticationContext": {
                    "authenticationStep": 0,
                    "externalSessionId": f"session-{random.randint(100000, 999999)}"
                },
                "debugContext": {
                    "debugData": {
                        "requestUri": "/api/v1/authn",
                        "factor": random.choice(cls.AUTH_METHODS)
                    }
                }
            }
            events.append(event)
        
        return events
    
    @classmethod
    def get_sample_collection(cls, collection_name: str, filter_query: Dict = None, days: int = 30):
        """
        Simulate MongoDB collection queries with sample data.
        Returns a cursor-like object that supports common operations.
        """
        if collection_name == "okta_logs":
            events = cls.generate_events(count=500, days=days)
            
            # Apply basic filtering if provided
            if filter_query:
                filtered_events = []
                for event in events:
                    match = True
                    
                    # Handle published date filtering
                    if 'published' in filter_query:
                        if '$gte' in filter_query['published']:
                            if event['published'] < filter_query['published']['$gte']:
                                match = False
                        if '$lt' in filter_query['published']:
                            if event['published'] >= filter_query['published']['$lt']:
                                match = False
                    
                    # Handle outcome filtering
                    if 'outcome.result' in filter_query:
                        if event['outcome']['result'] != filter_query['outcome.result']:
                            match = False
                    
                    # Handle eventType filtering
                    if 'eventType' in filter_query:
                        if isinstance(filter_query['eventType'], dict):
                            if '$regex' in filter_query['eventType']:
                                import re
                                if not re.search(filter_query['eventType']['$regex'], event['eventType']):
                                    match = False
                        elif event['eventType'] != filter_query['eventType']:
                            match = False
                    
                    if match:
                        filtered_events.append(event)
                
                events = filtered_events
            
            return SampleCursor(events)
        
        return SampleCursor([])


class SampleCursor:
    """Mock cursor object that mimics PyMongo cursor behavior."""
    
    def __init__(self, data: List[Dict]):
        self.data = data
        self._index = 0
    
    def __iter__(self):
        return iter(self.data)
    
    def __next__(self):
        if self._index < len(self.data):
            result = self.data[self._index]
            self._index += 1
            return result
        raise StopIteration
    
    def count(self):
        """Return count of documents."""
        return len(self.data)
    
    def limit(self, limit: int):
        """Limit results."""
        self.data = self.data[:limit]
        return self
    
    def sort(self, key: str, direction: int = 1):
        """Sort results."""
        reverse = direction == -1
        
        # Handle nested keys
        def get_nested(obj, key_path):
            keys = key_path.split('.')
            val = obj
            for k in keys:
                val = val.get(k, '')
            return val
        
        self.data = sorted(self.data, key=lambda x: get_nested(x, key), reverse=reverse)
        return self
    
    def skip(self, skip: int):
        """Skip N documents."""
        self.data = self.data[skip:]
        return self
    
    def count_documents(self, filter_query: Dict = None):
        """Return count (for compatibility)."""
        return len(self.data)
