# login_tracking/api_views.py
import hmac, hashlib
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from apps.analytics.models import OktaEvent
from .utils import compute_avg_okta_login_time_from_mongo, get_cached_avg_login_time, calculate_total_login_events

@api_view(['GET'])
@permission_classes([IsAdminUser])
def okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    avg = compute_avg_okta_login_time_from_mongo(days)
    if avg is None:
        return Response({'avg_login_time_sec': None, 'message': 'No valid login events found.'}, status=204)
    return Response({'avg_login_time_ms': avg})

@api_view(['GET'])
@permission_classes([AllowAny])
def cached_okta_login_time(request):
    days = int(request.query_params.get('days', 1))
    data = get_cached_avg_login_time(days)
    return Response({
        'avg_ms': data['avg_ms'],
        'last_updated': data['timestamp'],
        'trend_value': data['trend_value'],
    })

@api_view(['GET'])
@permission_classes([IsAdminUser])
def total_login_events(request):
    """
    Get the total number of login events (user.session.start) from the last specified number of days.
    
    Query Parameters:
    - days: Number of days to look back (default: 30)
    """
    days = int(request.query_params.get('days', 30))
    count = calculate_total_login_events(days)
    return Response({
        'total_count': count,
        'days': days,
        'event_type': 'user.session.start'
    })
