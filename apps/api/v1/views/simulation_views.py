import logging
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django_ratelimit.decorators import ratelimit

from apps.analytics.services.event_simulation import OktaEventSimulator as EventSimulator

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
@ratelimit(key='user', rate='10/m')
def generate_simulation(request):
    """
    Generate simulated Okta events for testing and demonstration.
    
    This endpoint is restricted to admin users and is primarily used
    for development, testing, and demonstration purposes.
    """
    # Check if simulation is allowed in this environment
    if not settings.DEBUG and not getattr(settings, 'ALLOW_SIMULATION', False):
        logger.warning(f"Simulation attempt in production by {request.user.username}")
        return Response(
            {"error": "Event simulation is only available in development environments"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Get parameters
    event_count = int(request.data.get('event_count', 100))
    event_types = request.data.get('event_types', [])
    include_threats = request.data.get('include_threats', False)
    time_span_days = int(request.data.get('time_span_days', 7))
    
    # Limit the maximum number of events per request
    if event_count > 1000:
        event_count = 1000
    
    try:
        # Create an event simulator
        simulator = EventSimulator()
        
        # Generate events
        generated_events = simulator.generate_events(
            count=event_count,
            event_types=event_types,
            include_threats=include_threats,
            time_span_days=time_span_days
        )
        
        # Save to database
        saved_count = simulator.save_events(generated_events)
        
        # Also generate metrics based on events
        simulator.generate_metrics_from_events(generated_events)
        
        # Log the simulation
        logger.info(f"User {request.user.username} simulated {saved_count} events")
        
        return Response({
            "success": True,
            "message": f"Generated and saved {saved_count} events",
            "event_count": saved_count
        })
        
    except Exception as e:
        logger.error(f"Error generating simulation: {str(e)}")
        return Response(
            {"error": f"Failed to generate simulation: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )