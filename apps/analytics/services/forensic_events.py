"""
Forensic Events Service for Okta Dashboard

This module provides functionality for digital forensics analysis of Okta authentication events,
capturing and analyzing forensic evidence for security investigations.
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any

from django.utils import timezone
from django.conf import settings
from django.core.cache import cache

from apps.analytics.models import OktaEvent, ForensicEvent
from core.services.okta_client import OktaApiClient

logger = logging.getLogger(__name__)


class ForensicEventsService:
    """
    Service for digital forensics analysis of Okta authentication events.
    
    This service provides methods to:
    - Capture and store forensic evidence from authentication events
    - Create audit trails for user activities
    - Generate hash-based evidence verification
    - Support investigations of security incidents
    """
    
    def __init__(self, okta_client: Optional[OktaApiClient] = None):
        """
        Initialize the forensic events service.
        
        Args:
            okta_client: An instance of OktaApiClient or None to create a new one
        """
        self.okta_client = okta_client or OktaApiClient()
    
    def capture_forensic_evidence(self, okta_event_id: str) -> Dict[str, Any]:
        """
        Capture and store forensic evidence for a specific Okta event.
        
        Args:
            okta_event_id: The Okta event ID to capture forensic evidence for
        
        Returns:
            Dictionary containing the forensic event data
        """
        # Check if evidence already exists
        existing_evidence = ForensicEvent.objects(source_event_id=okta_event_id).first()
        if existing_evidence:
            return existing_evidence.to_mongo().to_dict()
            
        # Get the Okta event from database or API
        okta_event = OktaEvent.objects(event_id=okta_event_id).first()
        if not okta_event:
            # Try to get from API if not in database
            events = self.okta_client.get_user_logs(
                filter_query=f'eventId eq "{okta_event_id}"',
                limit=1
            )
            if not events:
                raise ValueError(f"Could not find Okta event with ID {okta_event_id}")
            
            # Create event object from API response
            event_data = events[0]
            okta_event = OktaEvent(
                event_id=event_data.get('eventId', okta_event_id),
                event_type=event_data.get('eventType', ''),
                published=event_data.get('published', datetime.now()),
                actor=event_data.get('actor', {}),
                target=event_data.get('target', []),
                outcome=event_data.get('outcome', {}),
                client=event_data.get('client', {})
            )
            okta_event.save()
        
        # Extract relevant forensic data
        event_data = okta_event.to_mongo().to_dict()
        
        # Create evidence hash for data integrity verification
        evidence_string = json.dumps(event_data, sort_keys=True)
        evidence_hash = hashlib.sha256(evidence_string.encode()).hexdigest()
        
        # Extract user ID if available
        user_id = None
        if okta_event.actor and 'id' in okta_event.actor:
            user_id = okta_event.actor['id']
        
        # Extract IP address if available
        ip_address = okta_event.ip_address
        
        # Extract device info if available
        device_info = {}
        if okta_event.client and 'device' in okta_event.client:
            device_info = okta_event.client.get('device', {})
        
        # Extract user agent if available
        user_agent = None
        if okta_event.client and 'userAgent' in okta_event.client:
            user_agent = okta_event.client.get('userAgent', {}).get('rawUserAgent')
        
        # Extract geo location if available
        geo_location = {}
        if okta_event.client and 'geographicalContext' in okta_event.client:
            geo_location = okta_event.client.get('geographicalContext', {})
        
        # Determine action and resource
        action = "unknown"
        resource = "unknown"
        
        if "authentication" in okta_event.event_type:
            action = "authentication"
            resource = "user_session"
        elif "application" in okta_event.event_type:
            action = "access"
            resource = "application"
            # Try to extract app name from target
            if okta_event.target:
                for target in okta_event.target:
                    if target.get('type') == 'AppInstance':
                        resource = target.get('displayName', 'application')
                        break
        
        # Determine status from outcome
        status = "unknown"
        if okta_event.outcome and 'result' in okta_event.outcome:
            status = okta_event.outcome['result'].lower()
        
        # Create forensic context
        context = {
            'evidence_hash': evidence_hash,
            'source_event': okta_event_id,
            'collection_time': datetime.now().isoformat(),
            'collection_method': 'automated_service'
        }
        
        # Create and save forensic event
        forensic_event = ForensicEvent(
            event_id=f"forensic_{uuid.uuid4().hex}",
            source_event_id=okta_event_id,
            timestamp=okta_event.published,
            event_type=okta_event.event_type,
            severity=okta_event.severity,
            user_id=user_id,
            username=okta_event.actor.get('displayName') if okta_event.actor else None,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            session_id=okta_event.client.get('sessionId') if okta_event.client else None,
            geo_location=geo_location,
            resource=resource,
            action=action,
            status=status,
            context=context,
            raw_data=json.dumps(event_data)
        )
        forensic_event.save()
        
        return forensic_event.to_mongo().to_dict()
    
    def get_forensic_events(self,
                           start_time: Optional[datetime] = None,
                           end_time: Optional[datetime] = None,
                           user_id: Optional[str] = None,
                           event_type: Optional[str] = None,
                           limit: int = 100) -> List[Dict]:
        """
        Get forensic events with optional filtering.
        
        Args:
            start_time: Beginning of time range
            end_time: End of time range
            user_id: Filter by user ID
            event_type: Filter by event type
            limit: Maximum number of events to return
            
        Returns:
            List of forensic events as dictionaries
        """
        # Set default time range if not specified
        if not start_time:
            start_time = timezone.now() - timedelta(days=30)
        if not end_time:
            end_time = timezone.now()
        
        # Build query
        query = {
            "timestamp__gte": start_time,
            "timestamp__lte": end_time
        }
        
        # Apply filters if provided
        if user_id:
            query["user_id"] = user_id
        if event_type:
            query["event_type"] = event_type
        
        # Execute query with limit and sort
        forensic_events = list(ForensicEvent.objects(**query).order_by('-timestamp').limit(limit))
        
        # Convert to dictionaries
        return [event.to_mongo().to_dict() for event in forensic_events]
    
    def verify_evidence_integrity(self, forensic_event_id: str) -> Dict[str, Any]:
        """
        Verify the integrity of forensic evidence.
        
        Args:
            forensic_event_id: The forensic event ID to verify
            
        Returns:
            Dictionary with verification result
        """
        # Get the forensic event
        forensic_event = ForensicEvent.objects(event_id=forensic_event_id).first()
        if not forensic_event:
            return {
                'verified': False,
                'error': f"Could not find forensic event with ID {forensic_event_id}"
            }
        
        # Get the stored hash from context
        stored_hash = forensic_event.context.get('evidence_hash')
        if not stored_hash:
            return {
                'verified': False,
                'error': "No evidence hash found in forensic event"
            }
        
        # Get related Okta event
        okta_event = OktaEvent.objects(event_id=forensic_event.source_event_id).first()
        if not okta_event:
            return {
                'verified': False,
                'error': f"Could not find related Okta event with ID {forensic_event.source_event_id}"
            }
        
        # Recalculate hash
        event_data = okta_event.to_mongo().to_dict()
        evidence_string = json.dumps(event_data, sort_keys=True)
        calculated_hash = hashlib.sha256(evidence_string.encode()).hexdigest()
        
        # Compare hashes
        is_verified = stored_hash == calculated_hash
        
        return {
            'verified': is_verified,
            'stored_hash': stored_hash,
            'calculated_hash': calculated_hash,
            'timestamp': datetime.now().isoformat(),
            'forensic_event_id': forensic_event_id,
            'okta_event_id': forensic_event.source_event_id
        }


# Helper function to process a batch of Okta events and create forensic evidence
def process_forensic_events(event_ids: List[str]) -> List[Dict]:
    """
    Process a batch of Okta events and create forensic evidence.
    
    Args:
        event_ids: List of Okta event IDs to process
        
    Returns:
        List of processing results
    """
    service = ForensicEventsService()
    results = []
    
    for event_id in event_ids:
        try:
            forensic_event = service.capture_forensic_evidence(event_id)
            results.append({
                'event_id': event_id,
                'forensic_event_id': forensic_event.get('event_id'),
                'status': 'success'
            })
        except Exception as e:
            logger.error(f"Error processing forensic evidence for event {event_id}: {str(e)}")
            results.append({
                'event_id': event_id,
                'status': 'error',
                'error': str(e)
            })
    
    return results