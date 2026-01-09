"""
Django management command to populate MongoDB with realistic sample Okta log data.

Usage:
    python manage.py populate_sample_data --count 50000
"""

import random
import datetime
import uuid
from django.core.management.base import BaseCommand
from django.conf import settings
from core.services.database import DatabaseService


class Command(BaseCommand):
    help = 'Populate MongoDB with sample Okta log data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=50000,
            help='Number of sample log entries to generate (default: 50000)'
        )
        parser.add_argument(
            '--days',
            type=int,
            default=90,
            help='Number of days to spread the data across (default: 90)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing sample data before populating'
        )
        parser.add_argument(
            '--target',
            choices=['real', 'sample'],
            default='real',
            help="Target database to populate: 'real' or 'sample' (default: real)"
        )

    def handle(self, *args, **options):
        count = options['count']
        days = options['days']
        clear = options['clear']
        target = options['target']

        self.stdout.write(self.style.SUCCESS(f'Starting to generate {count} sample Okta log entries...'))

        # Access MongoDB client directly
        db_service = DatabaseService()
        # Directly access MongoDB client to bypass sample data routing
        if not db_service.is_connected():
            db_service.connect()
        
        if target == 'sample':
            db_name = getattr(settings, 'MONGODB_SAMPLE_DB_NAME', settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB'))
        else:
            db_name = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
        collection = db_service.get_client()[db_name]['okta_logs']

        if clear:
            self.stdout.write('Clearing existing sample data...')
            result = collection.delete_many({'_sample_data': True})
            self.stdout.write(self.style.WARNING(f'Deleted {result.deleted_count} sample entries'))

        # Generate and insert sample data
        generator = SampleOktaDataGenerator(days=days)
        batch_size = 1000
        total_inserted = 0

        for i in range(0, count, batch_size):
            batch_count = min(batch_size, count - i)
            events = [generator.generate_event() for _ in range(batch_count)]
            
            try:
                collection.insert_many(events, ordered=False)
                total_inserted += batch_count
                
                # Progress indicator
                percent = (total_inserted / count) * 100
                self.stdout.write(f'Progress: {total_inserted}/{count} ({percent:.1f}%)', ending='\r')
                self.stdout.flush()
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'\nError inserting batch: {e}'))

        self.stdout.write(self.style.SUCCESS(f'\n✓ Successfully inserted {total_inserted} sample log entries'))


class SampleOktaDataGenerator:
    """Generate realistic Okta log entries."""
    
    # Sample data pools
    FIRST_NAMES = [
        "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
        "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
        "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
        "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
        "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle"
    ]
    
    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
        "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
        "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
        "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
        "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores"
    ]
    
    DOMAINS = [
        "company.com", "enterprise.com", "corp.com", "business.com", "organization.com"
    ]
    
    APPLICATIONS = [
        # Real enterprise SaaS apps with usage-weighted distribution
        # High-traffic apps (Salesforce, Slack, MS365) have higher weights
        {"id": "0oa1", "name": "Salesforce", "type": "SAML_2_0", "weight": 15},
        {"id": "0oa2", "name": "Slack", "type": "SAML_2_0", "weight": 14},
        {"id": "0oa3", "name": "Google Workspace", "type": "SAML_2_0", "weight": 12},
        {"id": "0oa4", "name": "Microsoft 365", "type": "SAML_2_0", "weight": 13},
        {"id": "0oa5", "name": "Zoom", "type": "SAML_2_0", "weight": 8},
        {"id": "0oa6", "name": "AWS Console", "type": "SAML_2_0", "weight": 10},
        {"id": "0oa7", "name": "GitHub", "type": "SAML_2_0", "weight": 7},
        {"id": "0oa8", "name": "Jira", "type": "BOOKMARK", "weight": 6},
        {"id": "0oa9", "name": "Confluence", "type": "BOOKMARK", "weight": 5},
        {"id": "0oaa", "name": "ServiceNow", "type": "SAML_2_0", "weight": 3},
        {"id": "0oab", "name": "Workday", "type": "SAML_2_0", "weight": 4},
        {"id": "0oac", "name": "Azure Portal", "type": "SAML_2_0", "weight": 2},
        {"id": "0oad", "name": "Dropbox", "type": "SAML_2_0", "weight": 1},
    ]
    
    LOCATIONS = [
        # Geographic locations weighted by real traffic distribution from Okta analysis
        # Chicago > Paris > LA > Houston > NY > London > Phoenix > Tokyo > SF > Berlin > Boston > Toronto > Seattle > Sydney
        {"city": "Chicago", "state": "Illinois", "country": "United States", "lat": 41.8781, "lon": -87.6298, "weight": 15},
        {"city": "Paris", "state": "", "country": "France", "lat": 48.8566, "lon": 2.3522, "weight": 11},
        {"city": "Los Angeles", "state": "California", "country": "United States", "lat": 34.0522, "lon": -118.2437, "weight": 10},
        {"city": "Houston", "state": "Texas", "country": "United States", "lat": 29.7604, "lon": -95.3698, "weight": 9},
        {"city": "New York", "state": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060, "weight": 8},
        {"city": "London", "state": "", "country": "United Kingdom", "lat": 51.5074, "lon": -0.1278, "weight": 8},
        {"city": "Phoenix", "state": "Arizona", "country": "United States", "lat": 33.4484, "lon": -112.0740, "weight": 7},
        {"city": "Tokyo", "state": "", "country": "Japan", "lat": 35.6762, "lon": 139.6503, "weight": 6},
        {"city": "San Francisco", "state": "California", "country": "United States", "lat": 37.7749, "lon": -122.4194, "weight": 5},
        {"city": "Berlin", "state": "", "country": "Germany", "lat": 52.5200, "lon": 13.4050, "weight": 5},
        {"city": "Boston", "state": "Massachusetts", "country": "United States", "lat": 42.3601, "lon": -71.0589, "weight": 5},
        {"city": "Toronto", "state": "Ontario", "country": "Canada", "lat": 43.6532, "lon": -79.3832, "weight": 4},
        {"city": "Seattle", "state": "Washington", "country": "United States", "lat": 47.6062, "lon": -122.3321, "weight": 3},
        {"city": "Sydney", "state": "New South Wales", "country": "Australia", "lat": -33.8688, "lon": 151.2093, "weight": 2},
    ]
    
    EVENT_TYPES = [
        # Event types with realistic frequency weights and success rates
        # Based on real Okta data analysis: session.start 30.1%, sso 25.1%, mfa 14.7%, etc.
            ("user.session.start", "User login to Okta", 0.301, "SUCCESS", 0.949),
            ("user.authentication.sso", "User single sign on to app", 0.251, "SUCCESS", 0.95),
            ("user.authentication.auth_via_mfa", "Authentication of user via MFA", 0.147, "SUCCESS", 0.98),
            ("user.session.end", "User logout from Okta", 0.081, "SUCCESS", 1.0),
            ("policy.evaluate_sign_on", "Evaluation of sign-on policy", 0.08, "SUCCESS", 0.92),
            ("application.user_membership.add", "Add user to application membership", 0.051, "SUCCESS", 0.99),
            ("security.request.blocked", "Request blocked by security policy", 0.05, "FAILURE", 1.0),
            ("application.user_membership.remove", "Remove user from application membership", 0.021, "SUCCESS", 0.99),
            ("user.account.lock", "User account locked", 0.01, "FAILURE", 1.0),
            ("user.account.unlock", "User account unlocked", 0.01, "SUCCESS", 1.0),
    ]
    
    BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
    OS_TYPES = ["Windows 10", "Windows 11", "macOS", "Linux", "iOS", "Android"]
    DEVICE_TYPES = ["Computer", "Mobile", "Tablet"]
    
    MFA_FACTORS = [
        "Password", "SMS", "Email", "Google Authenticator", "Okta Verify", 
        "Duo Security", "YubiKey", "Password/IDP"
    ]
    
    def __init__(self, days=90):
        self.days = days
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.users = self._generate_user_pool(100)
        
    def _generate_user_pool(self, count):
        """Generate a pool of realistic users."""
        users = []
        for i in range(count):
            first = random.choice(self.FIRST_NAMES)
            last = random.choice(self.LAST_NAMES)
            domain = random.choice(self.DOMAINS)
            email = f"{first.lower()}.{last.lower()}@{domain}"
            
            users.append({
                "id": f"00u{uuid.uuid4().hex[:17]}",
                "email": email,
                "first_name": first,
                "last_name": last,
                "display_name": f"{first} {last}",
                "preferred_location": random.choice(self.LOCATIONS),
                "preferred_device": random.choice(self.DEVICE_TYPES),
                "preferred_browser": random.choice(self.BROWSERS),
                "preferred_os": random.choice(self.OS_TYPES),
            })
        return users
    
    def generate_event(self):
        """Generate a single realistic Okta log event."""
        # Timestamp with realistic day/hour distribution (peaks on weekdays and business hours)
        day_offset = self._pick_day_offset()
        event_date = self.now - datetime.timedelta(days=day_offset)
        hour = self._pick_hour()
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        event_time = event_date.replace(hour=hour, minute=minute, second=second, microsecond=0)
        # Guard against future timestamps when day_offset=0 and hour>now
        if event_time > self.now:
            event_time = self.now - datetime.timedelta(minutes=random.randint(0, 59))
        
        # Select user and event type
        user = random.choice(self.users)
        event_type, display_msg, _, outcome_type, success_rate = random.choices(
            self.EVENT_TYPES,
            weights=[e[2] for e in self.EVENT_TYPES]
        )[0]
        
        # Determine outcome
        outcome_result = outcome_type if random.random() < success_rate else (
            "FAILURE" if outcome_type == "SUCCESS" else "SUCCESS"
        )
        
        # Select location with weighted geographic distribution
        location = self._select_weighted_location(user["preferred_location"])
        
        # Select device info (80% preferred)
        device_type = user["preferred_device"] if random.random() < 0.8 else random.choice(self.DEVICE_TYPES)
        browser = user["preferred_browser"] if random.random() < 0.8 else random.choice(self.BROWSERS)
        os_type = user["preferred_os"] if random.random() < 0.8 else random.choice(self.OS_TYPES)
        
        # Select application with weighted realistic distribution
        app = self._select_weighted_application()
        
        # Generate event ID
        event_id = f"evt{uuid.uuid4().hex[:24]}"
        
        # Build the event document
        event = {
            "_sample_data": True,  # Mark as sample data for easy cleanup
            "uuid": event_id,
            "published": event_time.isoformat().replace('+00:00', 'Z'),
            "eventType": event_type,
            "version": "0",
            "severity": "INFO",
            "legacyEventType": event_type.replace(".", "_").upper(),
            "displayMessage": display_msg,
            "actor": {
                "id": user["id"],
                "type": "User",
                "alternateId": user["email"],
                "displayName": user["display_name"],
                "detailEntry": None
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": f"{browser}/100.0 ({os_type})",
                    "os": os_type,
                    "browser": browser
                },
                "zone": "null",
                "device": device_type,
                "id": None,
                "ipAddress": self._generate_ip(),
                "geographicalContext": {
                    "city": location["city"],
                    "state": location["state"],
                    "country": location["country"],
                    "postalCode": None,
                    "geolocation": {
                        "lat": location["lat"],
                        "lon": location["lon"]
                    }
                }
            },
            "outcome": {
                "result": outcome_result,
                "reason": self._get_outcome_reason(event_type, outcome_result)
            },
            "target": [
                {
                    "id": app["id"] + uuid.uuid4().hex[:12],
                    "type": "AppInstance",
                    "alternateId": app["name"],
                    "displayName": app["name"],
                    "detailEntry": {
                        "signOnModeType": app["type"]
                    }
                }
            ],
            "transaction": {
                "type": "WEB",
                "id": f"Wtr{uuid.uuid4().hex[:24]}",
                "detail": {}
            },
            "debugContext": {
                "debugData": {
                    "requestUri": self._get_request_uri(event_type),
                    "factor": random.choice(self.MFA_FACTORS) if "mfa" in event_type or "auth" in event_type else None,
                    "behaviors": f"New Geo-Location={random.choice(['true', 'false'])}",
                }
            },
            "authenticationContext": {
                "authenticationProvider": None,
                "credentialProvider": None,
                "credentialType": None,
                "issuer": None,
                "externalSessionId": f"trs{uuid.uuid4().hex[:24]}",
                "interface": None,
                "authenticationStep": 0
            },
            "securityContext": {
                "asNumber": random.randint(10000, 99999),
                "asOrg": random.choice(["comcast cable", "verizon", "att", "google", "amazon"]),
                "isp": random.choice(["Comcast Cable", "Verizon", "AT&T", "Google Fiber", "Amazon"]),
                "domain": user["email"].split("@")[1],
                "isProxy": False
            },
            "request": {
                "ipChain": [
                    {
                        "ip": self._generate_ip(),
                        "geographicalContext": {
                            "city": location["city"],
                            "state": location["state"],
                            "country": location["country"],
                            "postalCode": None,
                            "geolocation": {
                                "lat": location["lat"],
                                "lon": location["lon"]
                            }
                        },
                        "version": "V4",
                        "source": None
                    }
                ]
            }
        }
        
        return event

    def _select_weighted_location(self, preferred_location):
        """Select location with realistic geographic distribution.
        85% of time uses user's preferred location, 15% chooses from other
        locations based on weighted distribution.
        """
        if random.random() < 0.85:  # 85% use preferred location
            return preferred_location

        # 15% pick from other locations, weighted by popularity
        return random.choices(
            self.LOCATIONS,
            weights=[loc.get("weight", 1) for loc in self.LOCATIONS]
        )[0]

    def _select_weighted_application(self):
        """Select application with realistic frequency distribution.
        High-traffic apps (Salesforce, Slack, Microsoft 365) appear more often,
        matching real enterprise SaaS adoption patterns.
        """
        return random.choices(
            self.APPLICATIONS,
            weights=[app.get("weight", 1) for app in self.APPLICATIONS]
        )[0]

    def _pick_day_offset(self):
        """Pick a day offset with weekday preference (weekends lighter)."""
        weights = []
        options = list(range(self.days))
        for d in options:
            day = (self.now - datetime.timedelta(days=d)).weekday()  # 0=Mon
            weights.append(1.0 if day < 5 else 0.35)  # weekends ~35% of weekday volume
        return random.choices(options, weights=weights)[0]

    def _pick_hour(self):
        """Pick hour with business-hour peaks and evening shoulder."""
        hour_weights = [
            0.5, 0.5, 0.5, 0.5, 0.6, 0.8, 1.5, 2.5, 4.0, 4.5, 4.5, 4.0,
            3.0, 3.5, 3.5, 3.0, 2.5, 2.0, 1.5, 1.0, 0.8, 0.6, 0.5, 0.5
        ]
        return random.choices(list(range(24)), weights=hour_weights)[0]

    def _generate_ip(self):
        """Generate a random but realistic IP address."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _get_outcome_reason(self, event_type, outcome):
        """Get appropriate outcome reason."""
        if outcome == "SUCCESS":
            return None
        
        reasons = {
            "user.session.start": "INVALID_CREDENTIALS",
            "user.authentication.sso": "INVALID_CREDENTIALS",
            "user.authentication.auth_via_mfa": "VERIFICATION_ERROR",
            "policy.evaluate_sign_on": "DENY_POLICY",
            "security.request.blocked": "THREAT_DETECTED",
        }
        return reasons.get(event_type, "UNKNOWN")
    
    def _get_request_uri(self, event_type):
        """Get appropriate request URI for event type."""
        uris = {
            "user.session.start": "/api/v1/authn",
            "user.authentication.sso": "/app/[appname]/sso/saml",
            "user.authentication.auth_via_mfa": "/api/v1/authn/factors/verify",
            "application.user_membership.add": "/api/v1/apps/[appid]/users",
            "application.user_membership.remove": "/api/v1/apps/[appid]/users/[userid]",
            "user.session.end": "/api/v1/sessions/me",
            "policy.evaluate_sign_on": "/api/v1/policy/evaluate",
        }
        return uris.get(event_type, "/api/v1/logs")
