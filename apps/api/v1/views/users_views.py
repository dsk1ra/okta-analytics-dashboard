import logging
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_ratelimit.decorators import ratelimit
from datetime import datetime, timedelta

from apps.analytics.models import OktaUserProfile
from apps.api.v1.serializers.user_serializers import (
    OktaUserProfileSerializer,
    OktaUserDetailSerializer,
    OktaUserRiskSerializer
)

logger = logging.getLogger(__name__)

class UsersViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving and analyzing Okta user profiles.
    
    This viewset provides access to user data with security awareness.
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['status']
    search_fields = ['username', 'email', 'display_name']
    ordering = ['-last_login']  # Default ordering
    
    def get_serializer_class(self):
        """Return the appropriate serializer based on action"""
        if self.action == 'retrieve':
            return OktaUserDetailSerializer
        elif self.action == 'risk_assessment':
            return OktaUserRiskSerializer
        return OktaUserProfileSerializer
    
    def get_queryset(self):
        """
        Get the base queryset with optimized query patterns
        """
        status = self.request.query_params.get('status')
        risk_threshold = self.request.query_params.get('risk_threshold')
        
        # Base query - using optimized indexes
        queryset = OktaUserProfile.objects()
        
        # Apply filters if provided
        if status:
            queryset = queryset.filter(status=status)
            
        if risk_threshold:
            try:
                threshold = float(risk_threshold)
                queryset = queryset.filter(risk_score__gte=threshold)
            except ValueError:
                pass
            
        return queryset
    
    @method_decorator(cache_page(60 * 10))  # Cache for 10 minutes
    @method_decorator(ratelimit(key='user', rate='30/m'))
    def list(self, request, *args, **kwargs):
        """List user profiles with pagination and filtering"""
        return super().list(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single user profile with details"""
        return super().retrieve(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 30))  # Cache for 30 minutes
    @action(detail=False, methods=['get'])
    def risk_assessment(self, request):
        """
        Get user risk assessment summary
        """
        # Get high risk users
        high_risk_threshold = float(request.query_params.get('threshold', 7.0))
        limit = int(request.query_params.get('limit', 50))
        
        # Use the optimized class method
        high_risk_users = OktaUserProfile.find_high_risk_users(high_risk_threshold, limit)
        
        # Calculate date for inactive users (60 days)
        inactive_cutoff = datetime.now() - timedelta(days=60)
        inactive_users = OktaUserProfile.find_inactive_users(inactive_cutoff, limit)
        
        # Prepare response data
        high_risk_data = OktaUserRiskSerializer(high_risk_users, many=True).data
        inactive_data = OktaUserRiskSerializer(inactive_users, many=True).data
        
        # Get statistics
        all_users_count = OktaUserProfile.objects.count()
        high_risk_count = OktaUserProfile.objects(risk_score__gte=high_risk_threshold).count()
        inactive_count = OktaUserProfile.objects(last_login__lte=inactive_cutoff).count()
        
        response_data = {
            'statistics': {
                'total_users': all_users_count,
                'high_risk_users': high_risk_count,
                'inactive_users': inactive_count,
                'high_risk_percentage': round((high_risk_count / all_users_count * 100), 2) if all_users_count > 0 else 0,
                'inactive_percentage': round((inactive_count / all_users_count * 100), 2) if all_users_count > 0 else 0,
            },
            'high_risk_users': high_risk_data,
            'inactive_users': inactive_data,
        }
        
        return Response(response_data)
    
    @action(detail=True, methods=['get'])
    def activity(self, request, pk=None):
        """
        Get user activity timeline
        """
        # Get the user profile
        try:
            user_profile = self.get_object()
        except OktaUserProfile.DoesNotExist:
            return Response(
                {"error": "User not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get time range parameters
        days = int(request.query_params.get('days', 30))
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Query for user events from the ForensicEvent model
        from apps.analytics.models import ForensicEvent
        
        events = ForensicEvent.get_user_timeline(
            user_profile.user_id,
            start_date,
            end_date,
            limit=100
        )
        
        # Format response data
        from apps.api.v1.serializers.forensics_serializers import ForensicEventSerializer
        events_data = ForensicEventSerializer(events, many=True).data
        
        response_data = {
            'user_id': user_profile.user_id,
            'username': user_profile.username or '',
            'time_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'events': events_data
        }
        
        return Response(response_data)