"""
Event simulation service for Okta Dashboard.

This module provides functionality for generating simulated Okta events for testing
and demonstration purposes.
"""

import json
import logging
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

import faker

from apps.analytics.models import OktaEvent, OktaMetrics

logger = logging.getLogger(__name__)


class OktaEventSimulator:
    """
    Service for generating simulated Okta events and metrics.
    
    This service provides methods to:
    - Generate realistic Okta event data for testing
    - Save generated events to database or file
    - Support different event types and patterns
    - Create metrics based on simulated events
    """
    
    def __init__(self):
        """Initialize the simulator with a Faker instance for generating realistic data."""
        self.fake = faker.Faker()
        
        # Common event types
        self.event_types = [
            'user.authentication.auth_via_mfa',
            'user.authentication.sso',
            'user.session.start',
            'user.session.end',
            'application.user_access',
            'user.mfa.factor.update',
            'user.mfa.factor.reset',
            'user.account.update_profile',
            'user.account.reset_password',
            'system.api_token.create',
            'security.threat.detected',
            'policy.evaluate_sign_on',
            'user.lifecycle.create',
            'user.lifecycle.activate'
        ]
        
        # Common user agent strings
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36 Edg/94.0.992.38',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
        ]
        
        # Sample IP addresses in different geographic locations
        self.ip_addresses = {
            'US': ['104.132.34.94', '72.21.196.65', '50.205.244.45'],
            'UK': ['82.132.213.88', '18.130.60.217', '195.188.24.133'],
            'Japan': ['111.108.54.10', '211.125.104.18', '126.78.212.80'],
            'Australia': ['1.42.119.20', '110.159.160.176', '203.219.38.122'],
            'Germany': ['217.89.31.60', '188.111.175.35', '78.137.141.20'],
            'Russia': ['213.180.204.8', '176.59.132.87', '109.173.75.91'],
            'China': ['183.136.225.35', '220.181.108.90', '123.58.180.7'],
            'Brazil': ['200.152.38.126', '201.86.100.50', '189.30.185.146'],
            'India': ['125.22.47.28', '202.142.71.33', '182.79.136.4']
        }
        
        # Attack patterns
        self.attack_vectors = [
            'password_spray',
            'credential_stuffing',
            'phishing',
            'account_takeover',
            'oauth_manipulation',
            'token_hijacking',
            'mfa_bypass',
            'session_hijacking',
            'api_abuse'
        ]
        
    def generate_events(self, 
                      count: int = 100, 
                      event_types: Optional[List[str]] = None, 
                      include_threats: bool = False,
                      time_span_days: int = 7) -> List[Dict[str, Any]]:
        """
        Generate a specified number of simulated Okta events.
        
        Args:
            count: Number of events to generate
            event_types: Optional list of specific event types to generate
            include_threats: Whether to include threat events
            time_span_days: Number of days to spread events over
            
        Returns:
            List of dictionaries representing Okta events
        """
        if not event_types:
            event_types = self.event_types
        
        events = []
        
        # Create realistic time distribution
        now = datetime.now()
        
        # Generate user IDs to use consistently
        user_ids = [f"00u{uuid.uuid4().hex[:16]}" for _ in range(5)]
        
        # Generate events
        for _ in range(count):
            # Pick an event type
            event_type = random.choice(event_types)
            
            # Create event timestamp within the time span
            offset = random.randint(0, time_span_days * 24 * 60 * 60)  # Random seconds within time span
            timestamp = now - timedelta(seconds=offset)
            
            # Generate risk level
            # Most events should be low/medium risk, with few high risk
            risk_probabilities = [('LOW', 0.7), ('MEDIUM', 0.25), ('HIGH', 0.05)]
            risk_level = random.choices(
                [level for level, _ in risk_probabilities],
                [prob for _, prob in risk_probabilities]
            )[0]
            
            # Determine if this should be a threat event
            threat_detected = False
            if include_threats and random.random() < 0.05:  # 5% chance of threat
                threat_detected = True
                risk_level = 'HIGH'  # Threats are always high risk
            
            # Generate basic event structure
            event = self._generate_base_event(event_type, timestamp, user_ids, risk_level, threat_detected)
            
            # Add specialized event details based on type
            if 'auth' in event_type or 'session.start' in event_type:
                self._add_auth_details(event, threat_detected)
            elif 'application' in event_type:
                self._add_application_details(event)
            elif 'mfa' in event_type:
                self._add_mfa_details(event)
            elif 'threat' in event_type:
                self._add_threat_details(event)
            
            events.append(event)
        
        return events
    
    def save_events(self, events: List[Dict[str, Any]]) -> int:
        """
        Save generated events to the database.
        
        Args:
            events: List of event dictionaries to save
            
        Returns:
            Number of events saved
        """
        saved_count = 0
        
        for event_data in events:
            try:
                # Check if the event already exists to avoid duplicates
                existing = OktaEvent.objects(event_id=event_data['event_id']).first()
                if existing:
                    continue
                
                # Create OktaEvent object
                event = OktaEvent(
                    event_id=event_data['event_id'],
                    event_type=event_data['event_type'],
                    display_message=event_data.get('display_message', ''),
                    published=event_data['published'],
                    severity=event_data.get('severity', 'INFO'),
                    actor=event_data.get('actor', {}),
                    target=event_data.get('target', []),
                    client=event_data.get('client', {}),
                    authentication_context=event_data.get('authentication_context', {}),
                    security_context=event_data.get('security_context', {}),
                    outcome=event_data.get('outcome', {}),
                    debug_context=event_data.get('debug_context', {}),
                    risk_level=event_data.get('risk_level', 'LOW'),
                    threat_detected=event_data.get('threat_detected', False),
                )
                
                # Save the event
                event.save()
                saved_count += 1
                
            except Exception as e:
                logger.error(f"Error saving simulated event: {str(e)}")
        
        return saved_count
    
    def generate_metrics_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate metrics based on simulated events.
        
        Args:
            events: List of event dictionaries to analyze
            
        Returns:
            List of generated metrics
        """
        metrics = []
        
        # Get time range from events
        timestamps = [datetime.fromisoformat(e['published'].replace('Z', '+00:00')) 
                     if isinstance(e['published'], str) else e['published'] for e in events]
        
        if not timestamps:
            return metrics
            
        start_date = min(timestamps).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = max(timestamps).replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Group events by day
        days = {}
        
        for event in events:
            timestamp = event['published'] if isinstance(event['published'], datetime) else datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
            day_key = timestamp.strftime('%Y-%m-%d')
            
            if day_key not in days:
                days[day_key] = []
                
            days[day_key].append(event)
        
        # Generate daily metrics
        for day, day_events in days.items():
            day_date = datetime.strptime(day, '%Y-%m-%d')
            
            # Count login attempts
            login_attempts = len([e for e in day_events if 'authentication' in e['event_type'] or 'session.start' in e['event_type']])
            
            # Count login failures
            login_failures = len([
                e for e in day_events 
                if ('authentication' in e['event_type'] or 'session.start' in e['event_type']) 
                and e.get('outcome', {}).get('result') == 'FAILURE'
            ])
            
            # Count MFA usage
            mfa_usage = len([e for e in day_events if 'mfa' in e['event_type']])
            
            # Count geo accesses
            geo_count = {}
            for event in day_events:
                if 'client' in event and 'geographicalContext' in event['client']:
                    country = event['client']['geographicalContext'].get('country', 'Unknown')
                    if country not in geo_count:
                        geo_count[country] = 0
                    geo_count[country] += 1
            
            # Create and save metrics
            metrics_data = [
                {
                    'metric_id': f"login_attempts_{day}",
                    'metric_type': 'login_attempts',
                    'time_period': 'daily',
                    'timestamp': day_date,
                    'end_timestamp': day_date + timedelta(days=1),
                    'value': login_attempts,
                    'data': {}
                },
                {
                    'metric_id': f"login_failures_{day}",
                    'metric_type': 'login_failures',
                    'time_period': 'daily',
                    'timestamp': day_date,
                    'end_timestamp': day_date + timedelta(days=1),
                    'value': login_failures,
                    'data': {}
                },
                {
                    'metric_id': f"mfa_usage_{day}",
                    'metric_type': 'mfa_usage',
                    'time_period': 'daily',
                    'timestamp': day_date,
                    'end_timestamp': day_date + timedelta(days=1),
                    'value': mfa_usage,
                    'data': {}
                },
                {
                    'metric_id': f"geo_access_{day}",
                    'metric_type': 'geo_access',
                    'time_period': 'daily',
                    'timestamp': day_date,
                    'end_timestamp': day_date + timedelta(days=1),
                    'value': sum(geo_count.values()),
                    'data': {'countries': geo_count}
                }
            ]
            
            # Save metrics to database
            for metric_data in metrics_data:
                try:
                    # Check if the metric already exists
                    existing = OktaMetrics.objects(metric_id=metric_data['metric_id']).first()
                    if existing:
                        continue
                        
                    # Create and save new metric
                    metric = OktaMetrics(
                        metric_id=metric_data['metric_id'],
                        metric_type=metric_data['metric_type'],
                        time_period=metric_data['time_period'],
                        timestamp=metric_data['timestamp'],
                        end_timestamp=metric_data['end_timestamp'],
                        value=metric_data['value'],
                        data=metric_data['data']
                    )
                    metric.save()
                    metrics.append(metric_data)
                    
                except Exception as e:
                    logger.error(f"Error saving simulated metric: {str(e)}")
        
        return metrics
    
    def save_to_file(self, events: List[Dict[str, Any]], filename: str) -> None:
        """
        Save generated events to a JSON file.
        
        Args:
            events: List of event dictionaries to save
            filename: Filename to save to
        """
        # Convert datetime objects to strings for JSON serialization
        serializable_events = []
        
        for event in events:
            serializable_event = event.copy()
            
            # Convert datetime to ISO format
            if isinstance(serializable_event.get('published'), datetime):
                serializable_event['published'] = serializable_event['published'].isoformat()
            
            serializable_events.append(serializable_event)
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(serializable_events, f, indent=2)
    
    def _generate_base_event(self, 
                           event_type: str, 
                           timestamp: datetime, 
                           user_ids: List[str],
                           risk_level: str,
                           threat_detected: bool) -> Dict[str, Any]:
        """
        Generate the base event structure.
        
        Args:
            event_type: Type of event to generate
            timestamp: Timestamp for the event
            user_ids: List of user IDs to choose from
            risk_level: Risk level for the event
            threat_detected: Whether this is a threat event
            
        Returns:
            Dictionary with base event data
        """
        # Pick a user from the list
        user_id = random.choice(user_ids)
        username = self.fake.user_name()
        email = f"{username}@{self.fake.domain_name()}"
        display_name = self.fake.name()
        
        # Pick a severity based on event type and risk
        severity_map = {
            'LOW': ['INFO', 'DEBUG'],
            'MEDIUM': ['INFO', 'WARNING'],
            'HIGH': ['WARNING', 'ERROR']
        }
        severity = random.choice(severity_map.get(risk_level, ['INFO']))
        
        # Pick a location
        country = random.choice(list(self.ip_addresses.keys()))
        ip_address = random.choice(self.ip_addresses[country])
        
        # Format display message based on event type
        display_message = self._format_display_message(event_type, username)
        
        # Create base event
        event = {
            'event_id': str(uuid.uuid4()),
            'event_type': event_type,
            'display_message': display_message,
            'published': timestamp,
            'severity': severity,
            'actor': {
                'id': user_id,
                'type': 'User',
                'alternateId': email,
                'displayName': display_name
            },
            'client': {
                'ipAddress': ip_address,
                'userAgent': {
                    'rawUserAgent': random.choice(self.user_agents)
                },
                'geographicalContext': {
                    'country': country,
                    'city': self.fake.city(),
                    'state': self.fake.state(),
                    'postalCode': self.fake.zipcode()
                }
            },
            'risk_level': risk_level,
            'threat_detected': threat_detected
        }
        
        return event
    
    def _format_display_message(self, event_type: str, username: str) -> str:
        """
        Create a human-readable display message for the event.
        
        Args:
            event_type: Type of event
            username: Username for the event
            
        Returns:
            Formatted message string
        """
        if 'authentication' in event_type or 'session.start' in event_type:
            return f"User {username} login to Okta"
        elif 'session.end' in event_type:
            return f"User {username} logout from Okta"
        elif 'application' in event_type:
            app = random.choice(['Salesforce', 'Office 365', 'Gmail', 'Slack', 'Jira'])
            return f"User {username} access to {app}"
        elif 'mfa' in event_type and 'update' in event_type:
            factor = random.choice(['SMS', 'Email', 'Okta Verify', 'Google Authenticator'])
            return f"User {username} updated {factor} factor"
        elif 'mfa' in event_type and 'reset' in event_type:
            factor = random.choice(['SMS', 'Email', 'Okta Verify', 'Google Authenticator'])
            return f"User {username} reset {factor} factor"
        elif 'account.update_profile' in event_type:
            return f"User {username} updated their profile"
        elif 'reset_password' in event_type:
            return f"Password reset for user {username}"
        elif 'threat.detected' in event_type:
            threat = random.choice(self.attack_vectors)
            return f"Security threat detected: {threat} affecting user {username}"
        elif 'policy.evaluate' in event_type:
            return f"Sign-on policy evaluation for user {username}"
        elif 'lifecycle.create' in event_type:
            return f"User {username} created"
        elif 'lifecycle.activate' in event_type:
            return f"User {username} activated"
        else:
            return f"Event {event_type} occurred for user {username}"
    
    def _add_auth_details(self, event: Dict[str, Any], is_threat: bool) -> None:
        """
        Add authentication-specific details to an event.
        
        Args:
            event: Event dictionary to modify
            is_threat: Whether this is a threat event
        """
        # Determine outcome based on threat flag and randomness
        # Most normal auths should succeed, most threats should fail
        outcome_result = 'SUCCESS'
        
        if is_threat:
            if random.random() < 0.8:  # 80% chance of failure for threats
                outcome_result = 'FAILURE'
        else:
            if random.random() < 0.05:  # 5% chance of failure for normal auths
                outcome_result = 'FAILURE'
        
        # Set outcome
        event['outcome'] = {
            'result': outcome_result
        }
        
        # Add failure reason if applicable
        if outcome_result == 'FAILURE':
            reasons = ['INVALID_CREDENTIALS', 'VERIFICATION_ERROR', 'INVALID_TOKEN', 'LOCKED_OUT']
            event['outcome']['reason'] = random.choice(reasons)
        
        # Add authentication context
        auth_provider = random.choice(['OKTA_AUTHENTICATION', 'ACTIVE_DIRECTORY', 'LDAP', 'FACTOR_PROVIDER'])
        
        event['authentication_context'] = {
            'authentication_provider': auth_provider,
            'authentication_step': random.randint(1, 2),  # 1 = primary, 2 = MFA
            'credential_provider': random.choice(['OKTA_CREDENTIAL_PROVIDER', 'RSA', 'AD_PASSWORD', 'OKTA_MFA']),
            'credential_type': random.choice(['PASSWORD', 'SMS', 'EMAIL', 'PUSH', 'TOTP']),
            'issuer': {
                'id': f"00o{uuid.uuid4().hex[:8]}",
                'type': "AUTH_SERVER"
            }
        }
        
        # Add security context for threats
        if is_threat:
            event['security_context'] = {
                'asNumber': random.randint(10000, 60000),
                'asOrg': self.fake.company(),
                'isp': self.fake.company(),
                'domain': self.fake.domain_name(),
                'isProxy': random.choice([True, False]),
                'threatSuspected': True,
                'threatType': random.choice(self.attack_vectors)
            }
    
    def _add_application_details(self, event: Dict[str, Any]) -> None:
        """Add application-specific details to an event."""
        app_id = f"0oa{uuid.uuid4().hex[:8]}"
        app_name = random.choice(['Salesforce', 'Office 365', 'Gmail', 'Slack', 'Jira', 'AWS Console', 'Zendesk'])
        
        # Add target for application events
        event['target'] = [
            {
                'id': app_id,
                'type': 'AppInstance',
                'alternateId': app_name,
                'displayName': app_name
            }
        ]
        
        # Add outcome (usually success for app access)
        event['outcome'] = {
            'result': random.choices(['SUCCESS', 'FAILURE'], weights=[0.95, 0.05])[0]
        }
    
    def _add_mfa_details(self, event: Dict[str, Any]) -> None:
        """Add MFA-specific details to an event."""
        factor_type = random.choice(['sms', 'email', 'push', 'token:software:totp', 'webauthn'])
        factor_id = f"mfa{uuid.uuid4().hex[:8]}"
        
        # Add MFA context
        event['authentication_context'] = {
            'authentication_step': 2,
            'credential_type': factor_type.upper(),
            'credential_provider': 'OKTA_MFA',
            'mfaDetail': {
                'factorProvider': 'OKTA',
                'factorType': factor_type
            }
        }
        
        # Add target for the MFA factor
        event['target'] = [
            {
                'id': factor_id,
                'type': 'AuthenticatorEnrollment',
                'alternateId': factor_type,
                'displayName': self._get_factor_display_name(factor_type)
            }
        ]
        
        # Add outcome (usually success for MFA operations)
        event['outcome'] = {
            'result': random.choices(['SUCCESS', 'FAILURE'], weights=[0.9, 0.1])[0]
        }
    
    def _add_threat_details(self, event: Dict[str, Any]) -> None:
        """Add threat-specific details to an event."""
        # Select an attack vector
        attack_vector = random.choice(self.attack_vectors)
        
        # Add security context
        event['security_context'] = {
            'asNumber': random.randint(10000, 60000),
            'asOrg': self.fake.company(),
            'isp': self.fake.company(),
            'domain': self.fake.domain_name(),
            'isProxy': True,
            'threatSuspected': True,
            'threatType': attack_vector
        }
        
        # Set severity to ERROR for threats
        event['severity'] = 'ERROR'
        
        # Set risk level to HIGH
        event['risk_level'] = 'HIGH'
        
        # Set threat detected flag
        event['threat_detected'] = True
        
        # Add debug context with additional information
        event['debug_context'] = {
            'debugData': {
                'requestId': str(uuid.uuid4()),
                'dtHash': str(uuid.uuid4().hex),
                'threat_indicators': [
                    'suspicious_ip_reputation',
                    'unusual_location',
                    'automated_request_pattern'
                ],
                'confidence_score': random.uniform(0.7, 0.98),
                'detection_time': datetime.now().isoformat()
            }
        }
    
    def _get_factor_display_name(self, factor_type: str) -> str:
        """Get display name for MFA factor type."""
        factor_names = {
            'sms': 'SMS Authentication',
            'email': 'Email Authentication',
            'push': 'Okta Verify Push',
            'token:software:totp': 'Okta Verify TOTP',
            'webauthn': 'WebAuthn Security Key'
        }
        return factor_names.get(factor_type, factor_type.capitalize())