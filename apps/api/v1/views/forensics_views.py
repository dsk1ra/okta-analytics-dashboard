"""
API views for forensic events and investigations.
"""

from datetime import datetime, timedelta
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

from apps.analytics.services.forensic_events import ForensicEventsService
from apps.analytics.models import ForensicEvent

# Rate limiting decorator for sensitive endpoints
forensic_ratelimit = method_decorator(
    ratelimit(key='user', rate='30/m', method='GET', block=True),
    name='dispatch'
)

# Function-based views for backward compatibility
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
def forensic_timeline(request):
    """
    Get forensic timeline of events.
    
    Query parameters:
    - since: Start date (ISO format)
    - until: End date (ISO format)
    - user_id: Filter by user ID
    """
    service = ForensicEventsService()
    
    # Process query parameters
    since = request.query_params.get('since')
    if since:
        try:
            since = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.now() - timedelta(days=30)
    else:
        since = datetime.now() - timedelta(days=30)
    
    until = request.query_params.get('until')
    if until:
        try:
            until = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            until = datetime.now()
    else:
        until = datetime.now()
    
    user_id = request.query_params.get('user_id')
    
    # Get timeline data
    timeline = service.get_forensic_timeline(since=since, until=until, user_id=user_id)
    return Response(timeline)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
def forensic_sessions(request):
    """
    Get forensic session analysis.
    
    Query parameters:
    - since: Start date (ISO format)
    - until: End date (ISO format)
    - user_id: Filter by user ID
    """
    service = ForensicEventsService()
    
    # Process query parameters
    since = request.query_params.get('since')
    if since:
        try:
            since = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.now() - timedelta(days=30)
    else:
        since = datetime.now() - timedelta(days=30)
    
    until = request.query_params.get('until')
    if until:
        try:
            until = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            until = datetime.now()
    else:
        until = datetime.now()
    
    user_id = request.query_params.get('user_id')
    
    # Get sessions data
    sessions = service.get_user_sessions(since=since, until=until, user_id=user_id)
    return Response(sessions)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
def geographic_analysis(request):
    """
    Get geographic analysis of authentication events.
    
    Query parameters:
    - since: Start date (ISO format)
    - until: End date (ISO format)
    - user_id: Filter by user ID
    """
    service = ForensicEventsService()
    
    # Process query parameters
    since = request.query_params.get('since')
    if since:
        try:
            since = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.now() - timedelta(days=30)
    else:
        since = datetime.now() - timedelta(days=30)
    
    until = request.query_params.get('until')
    if until:
        try:
            until = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            until = datetime.now()
    else:
        until = datetime.now()
    
    user_id = request.query_params.get('user_id')
    
    # Get geographic data
    geo_data = service.get_geographic_analysis(since=since, until=until, user_id=user_id)
    return Response(geo_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
def mfa_usage(request):
    """
    Get MFA usage analytics.
    
    Query parameters:
    - since: Start date (ISO format)
    - until: End date (ISO format)
    """
    service = ForensicEventsService()
    
    # Process query parameters
    since = request.query_params.get('since')
    if since:
        try:
            since = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.now() - timedelta(days=30)
    else:
        since = datetime.now() - timedelta(days=30)
    
    until = request.query_params.get('until')
    if until:
        try:
            until = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            until = datetime.now()
    else:
        until = datetime.now()
    
    # Get MFA usage data
    mfa_data = service.get_mfa_usage_analytics(since=since, until=until)
    return Response(mfa_data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
def zero_trust_metrics(request):
    """
    Get Zero Trust security metrics.
    
    Query parameters:
    - since: Start date (ISO format)
    - until: End date (ISO format)
    """
    service = ForensicEventsService()
    
    # Process query parameters
    since = request.query_params.get('since')
    if since:
        try:
            since = datetime.fromisoformat(since.replace('Z', '+00:00'))
        except ValueError:
            since = datetime.now() - timedelta(days=30)
    else:
        since = datetime.now() - timedelta(days=30)
    
    until = request.query_params.get('until')
    if until:
        try:
            until = datetime.fromisoformat(until.replace('Z', '+00:00'))
        except ValueError:
            until = datetime.now()
    else:
        until = datetime.now()
    
    # Get Zero Trust metrics
    metrics = service.get_zero_trust_metrics(since=since, until=until)
    return Response(metrics)


class ForensicEventsViewSet(viewsets.ViewSet):
    """
    API endpoints for forensic events and investigations.
    
    This viewset provides endpoints for:
    - Listing forensic events
    - Getting details of a specific event
    - Verifying evidence integrity
    - Creating investigations
    """
    permission_classes = [IsAuthenticated]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service = ForensicEventsService()
    
    @forensic_ratelimit
    def list(self, request):
        """
        List forensic events with filtering.
        
        Query parameters:
        - since: Start date (ISO format)
        - until: End date (ISO format)
        - user_id: Filter by user ID
        - event_type: Filter by event type
        - limit: Maximum number of events to return
        """
        # Process query parameters
        since = request.query_params.get('since')
        if since:
            try:
                since = datetime.fromisoformat(since.replace('Z', '+00:00'))
            except ValueError:
                since = datetime.now() - timedelta(days=30)
        else:
            since = datetime.now() - timedelta(days=30)
        
        until = request.query_params.get('until')
        if until:
            try:
                until = datetime.fromisoformat(until.replace('Z', '+00:00'))
            except ValueError:
                until = datetime.now()
        else:
            until = datetime.now()
        
        user_id = request.query_params.get('user_id')
        event_type = request.query_params.get('event_type')
        
        try:
            limit = int(request.query_params.get('limit', 100))
        except ValueError:
            limit = 100
        
        # Get events
        events = self.service.get_forensic_events(
            since=since,
            until=until,
            user_id=user_id,
            event_type=event_type,
            limit=limit
        )
        
        # Filter sensitive fields for security
        filtered_events = []
        for event in events:
            # Only include necessary fields
            filtered_event = {
                'event_id': event.get('event_id'),
                'related_okta_event_id': event.get('related_okta_event_id'),
                'timestamp': event.get('timestamp'),
                'event_type': event.get('event_type'),
                'user_id': event.get('user_id'),
                'username': event.get('username'),
                'ip_address': event.get('ip_address'),
                'severity': event.get('severity'),
                'risk_score': event.get('risk_score'),
                'summary': event.get('summary'),
                'country': event.get('country'),
                'city': event.get('city'),
            }
            filtered_events.append(filtered_event)
        
        return Response(filtered_events)
    
    @forensic_ratelimit
    def retrieve(self, request, pk=None):
        """
        Get details of a specific forensic event.
        """
        if not pk:
            return Response(
                {"error": "Event ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            event = self.service.get_forensic_event(pk)
            if not event:
                return Response(
                    {"error": "Event not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
                
            return Response(event)
            
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    @forensic_ratelimit
    def verify(self, request, pk=None):
        """
        Verify the integrity of forensic evidence.
        """
        if not pk:
            return Response(
                {"error": "Event ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            verification = self.service.verify_event_integrity(pk)
            return Response(verification)
            
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    @forensic_ratelimit
    def create_investigation(self, request):
        """
        Create a new investigation from forensic events.
        """
        # Get request data
        name = request.data.get('name')
        description = request.data.get('description')
        event_ids = request.data.get('event_ids', [])
        
        if not name or not event_ids:
            return Response(
                {"error": "Name and event_ids are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Create investigation
            investigation = self.service.create_investigation(
                name=name,
                description=description,
                event_ids=event_ids,
                created_by=request.user.username
            )
            
            return Response(investigation, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )