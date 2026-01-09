import logging
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django_filters.rest_framework import DjangoFilterBackend
from django_ratelimit.decorators import ratelimit

from apps.analytics.models import OktaMetrics
from apps.api.v1.serializers.metrics_serializers import (
    OktaMetricsSerializer,
    OktaMetricsSummarySerializer
)

logger = logging.getLogger(__name__)

class MetricsViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving and analyzing pre-aggregated Okta metrics.
    
    This viewset provides access to metrics data for dashboards and reports.
    """
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['metric_type', 'time_period']
    ordering = ['-timestamp']  # Default ordering
    
    def get_serializer_class(self):
        """Return the appropriate serializer based on action"""
        if self.action == 'summary':
            return OktaMetricsSummarySerializer
        return OktaMetricsSerializer
    
    def get_queryset(self):
        """
        Get the base queryset for metrics with optimized query patterns
        """
        # Get query parameters
        metric_type = self.request.query_params.get('metric_type')
        time_period = self.request.query_params.get('time_period', 'daily')
        days = int(self.request.query_params.get('days', 30))
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Base query
        queryset = OktaMetrics.objects(timestamp__gte=start_date, timestamp__lte=end_date)
        
        # Apply filters if provided
        if metric_type:
            queryset = queryset.filter(metric_type=metric_type)
        if time_period:
            queryset = queryset.filter(time_period=time_period)
            
        return queryset.order_by('-timestamp')
    
    @method_decorator(cache_page(60 * 15))  # Cache for 15 minutes
    @method_decorator(ratelimit(key='user', rate='30/m'))
    def list(self, request, *args, **kwargs):
        """List metrics with pagination and filtering"""
        return super().list(request, *args, **kwargs)
    
    @method_decorator(cache_page(60 * 60))  # Cache for 1 hour
    @method_decorator(ratelimit(key='user', rate='60/m'))
    @action(detail=False, methods=['get'])
    def summary(self, request):
        """
        Get a summary of metrics for dashboard display
        """
        # Get query parameters
        days = int(request.query_params.get('days', 30))
        time_period = request.query_params.get('time_period', 'daily')
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get metrics using the optimized class method
        login_metrics = OktaMetrics.get_recent_metrics('login_attempts', time_period, limit=days)
        failure_metrics = OktaMetrics.get_recent_metrics('login_failures', time_period, limit=days)
        mfa_metrics = OktaMetrics.get_recent_metrics('mfa_usage', time_period, limit=days)
        geo_metrics = OktaMetrics.get_recent_metrics('geo_access', time_period, limit=days)
        
        # Format response data
        summary = {
            'login_attempts': {
                'total': sum(m.value for m in login_metrics),
                'trend': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in login_metrics]
            },
            'login_failures': {
                'total': sum(m.value for m in failure_metrics),
                'trend': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in failure_metrics]
            },
            'mfa_usage': {
                'total': sum(m.value for m in mfa_metrics),
                'trend': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in mfa_metrics]
            },
            'geo_access': {
                'total': sum(m.value for m in geo_metrics),
                'trend': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in geo_metrics]
            },
            'time_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days,
                'granularity': time_period
            }
        }
        
        serializer = self.get_serializer(summary)
        return Response(serializer.data)
    
    @method_decorator(cache_page(60 * 30))  # Cache for 30 minutes
    @action(detail=False, methods=['get'])
    def comparison(self, request):
        """
        Get metrics comparison between two periods
        """
        # Current period
        days = int(request.query_params.get('days', 7))
        time_period = request.query_params.get('time_period', 'daily')
        metric_type = request.query_params.get('metric_type')
        
        if not metric_type:
            return Response(
                {"error": "metric_type parameter is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate date ranges
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        previous_end_date = start_date
        previous_start_date = previous_end_date - timedelta(days=days)
        
        # Get metrics for current period
        current_metrics = OktaMetrics.objects(
            metric_type=metric_type,
            time_period=time_period,
            timestamp__gte=start_date,
            timestamp__lte=end_date
        ).order_by('timestamp')
        
        # Get metrics for previous period
        previous_metrics = OktaMetrics.objects(
            metric_type=metric_type,
            time_period=time_period,
            timestamp__gte=previous_start_date,
            timestamp__lte=previous_end_date
        ).order_by('timestamp')
        
        # Calculate totals
        current_total = sum(m.value for m in current_metrics)
        previous_total = sum(m.value for m in previous_metrics)
        
        # Calculate percent change
        percent_change = 0
        if previous_total > 0:
            percent_change = ((current_total - previous_total) / previous_total) * 100
        
        # Format response data
        comparison = {
            'metric_type': metric_type,
            'current_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'total': current_total,
                'data': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in current_metrics]
            },
            'previous_period': {
                'start_date': previous_start_date.isoformat(),
                'end_date': previous_end_date.isoformat(),
                'total': previous_total,
                'data': [{'date': m.timestamp.isoformat(), 'value': m.value} for m in previous_metrics]
            },
            'comparison': {
                'absolute_change': current_total - previous_total,
                'percent_change': round(percent_change, 2)
            }
        }
        
        return Response(comparison)