"""
API views for Okta events.

This module provides ViewSets and API endpoints for retrieving and analyzing Okta events.
"""

import logging
from datetime import datetime, timedelta

from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_ratelimit.decorators import ratelimit

from apps.analytics.models import OktaEvent
from apps.api.v1.serializers.event_serializers import (
    OktaEventListSerializer, 
    OktaEventDetailSerializer,
    EventStatisticsSerializer
)

logger = logging.getLogger(__name__)

class EventsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving and analyzing Okta events.
    
    This viewset provides 'list' and 'retrieve' actions for Okta events 
    along with additional statistics endpoints.
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['event_type', 'severity', 'ip_address']
    search_fields = ['display_message', 'event_type', 'ip_address']
    ordering_fields = ['published', 'severity']
    ordering = ['-published']  # Default ordering
    
    def get_queryset(self):
        """
        Get the base queryset for the view, with optimized query patterns
        """
        # Default to past 7 days if no timeframe specified
        days = int(self.request.query_params.get('days', 7))
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        # Convert string dates to datetime if provided
        if start_date:
            try:
                start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                start_date = datetime.now() - timedelta(days=days)
        else:
            start_date = datetime.now() - timedelta(days=days)
            
        if end_date:
            try:
                end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                end_date = datetime.now()
        else:
            end_date = datetime.now()
                
        # Use optimized method from model
        return OktaEvent.get_events_by_timeframe(start_date, end_date)
    
    def get_serializer_class(self):
        """
        Return the appropriate serializer based on the action
        """
        if self.action == 'retrieve':
            return OktaEventDetailSerializer
        elif self.action == 'statistics':
            return EventStatisticsSerializer
        return OktaEventListSerializer
    
    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    @method_decorator(ratelimit(key='user', rate='30/m'))
    def list(self, request, *args, **kwargs):
        """
        List events with pagination and filtering
        """
        return super().list(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 15))  # Cache for 15 minutes
    @method_decorator(ratelimit(key='user', rate='60/m'))
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """
        Get event statistics for the dashboard
        """
        # Default to past 7 days if no timeframe specified
        days = int(request.query_params.get('days', 7))
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Calculate statistics from database using aggregation pipelines
        event_counts = OktaEvent.objects.aggregate([
            {
                '$match': {
                    'published': {'$gte': start_date, '$lte': end_date}
                }
            },
            {
                '$group': {
                    '_id': '$event_type',
                    'count': {'$sum': 1}
                }
            },
            {
                '$sort': {'count': -1}
            },
            {
                '$limit': 10
            }
        ])
        
        severity_counts = OktaEvent.objects.aggregate([
            {
                '$match': {
                    'published': {'$gte': start_date, '$lte': end_date}
                }
            },
            {
                '$group': {
                    '_id': '$severity',
                    'count': {'$sum': 1}
                }
            }
        ])
        
        # Format data for response
        event_type_data = {item['_id']: item['count'] for item in event_counts}
        severity_data = {item['_id']: item['count'] for item in severity_counts}
        
        data = {
            'event_types': event_type_data,
            'severities': severity_data,
            'time_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            }
        }
        
        serializer = self.get_serializer(data)
        return Response(serializer.data)
    
    @method_decorator(cache_page(60 * 10))  # Cache for 10 minutes
    @action(detail=False, methods=['get'])
    def threat_indicators(self, request):
        """
        Get threat indicators based on events
        """
        # Default to past 7 days
        days = int(request.query_params.get('days', 7))
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Find events with detected threats
        threat_events = OktaEvent.objects(
            published__gte=start_date,
            published__lte=end_date,
            threat_detected=True
        ).order_by('-published')[:100]  # Limit to 100 most recent
        
        # Find high risk events
        high_risk_events = OktaEvent.objects(
            published__gte=start_date,
            published__lte=end_date,
            risk_level='HIGH'
        ).order_by('-published')[:100]  # Limit to 100 most recent
        
        # Format response data
        threat_data = OktaEventListSerializer(threat_events, many=True).data
        risk_data = OktaEventListSerializer(high_risk_events, many=True).data
        
        return Response({
            'threat_events': threat_data,
            'high_risk_events': risk_data,
            'time_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            }
        })