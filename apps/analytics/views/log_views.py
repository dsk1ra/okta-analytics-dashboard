"""
Views for handling and displaying log statistics in a dashboard format.

This module contains both API and template-based views for log analysis,
providing professional dashboards for monitoring log statistics.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.utils import timezone
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q
from django.views.decorators.cache import cache_page
from django.utils.decorators import method_decorator

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django_ratelimit.decorators import ratelimit

from apps.analytics.services.event_service import LogAnalysisService
from apps.analytics.models import OktaEvent

import logging

logger = logging.getLogger(__name__)


class LogDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying professional log statistics dashboard in a user-friendly UI.
    Renders statistical visualizations of log data similar to the events dashboard.
    """
    template_name = 'traffic_analysis/logs/log_dashboard.html'
    login_url = '/login/'
    
    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    def get_context_data(self, **kwargs):
        """Add log statistics to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Get time period parameters
        days = int(self.request.GET.get('days', 30))
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get log statistics through the service layer
        service = LogAnalysisService()
        dashboard_metrics = service.get_log_dashboard_metrics(
            start_time=start_date,
            end_time=end_date
        )
        
        # Get comparison with previous period
        previous_start_date = start_date - timedelta(days=days)
        previous_end_date = end_date - timedelta(days=days)
        comparison_data = service.get_log_statistics_comparison(
            start_time=start_date,
            end_time=end_date,
            previous_start_time=previous_start_date,
            previous_end_time=previous_end_date
        )
        
        # Process data for charts
        severity_data = []
        for severity, count in dashboard_metrics["severity_distribution"].items():
            severity_data.append({
                "severity": severity,
                "count": count
            })
        
        # Format hourly distribution for time-based chart
        hourly_data = []
        for hour, count in enumerate(dashboard_metrics["hourly_distribution"]):
            hourly_data.append({
                "hour": f"{hour:02d}:00",
                "count": count
            })
        
        # Format daily trend data for line chart
        daily_trend = []
        for date, count in dashboard_metrics["daily_trend"].items():
            daily_trend.append({
                "date": date,
                "count": count
            })
        
        # Add data to context
        context.update({
            'days': days,
            'total_logs': dashboard_metrics["summary"]["total_logs"],
            'time_period': dashboard_metrics["summary"]["time_period"],
            'severity_distribution': severity_data,
            'hourly_distribution': hourly_data,
            'daily_trend': daily_trend,
            'top_sources': dashboard_metrics["top_sources"],
            'top_log_types': dashboard_metrics["top_log_types"],
            'comparison': comparison_data,
            'date_range_days': days,
            'available_time_ranges': [1, 7, 30, 90]
        })
        
        return context


class LogStatisticsAPIView(APIView):
    """
    API view for retrieving log statistics for dashboard visualizations.
    """
    permission_classes = [IsAuthenticated]
    
    @method_decorator(cache_page(60 * 5))  # Cache for 5 minutes
    @method_decorator(ratelimit(key='user', rate='30/m'))
    def get(self, request):
        """
        Handle GET requests for log statistics.
        
        Provides comprehensive statistics for dashboard display including
        severity distribution, time patterns, top sources and log types.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with formatted statistics for dashboard or error message
        """
        try:
            # Get query parameters
            days = int(request.query_params.get('days', 30))
            interval = request.query_params.get('interval', 'day')
            
            # Calculate date range
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            # Use the service to get dashboard metrics
            dashboard_metrics = LogAnalysisService.get_log_dashboard_metrics(
                start_time=start_date,
                end_time=end_date
            )
            
            # Get time-based volume metrics
            volume_by_time = LogAnalysisService.get_log_volume_by_timeframe(
                start_time=start_date,
                end_time=end_date,
                interval=interval
            )
            
            # Add volume metrics to the response
            dashboard_metrics["volume_by_time"] = volume_by_time
            
            return Response(dashboard_metrics)
        
        except Exception as e:
            logger.error(f"Failed to fetch log statistics: {str(e)}", exc_info=True)
            return Response(
                {"error": f"Failed to fetch log statistics: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogComparisonView(APIView):
    """
    API view for comparing log statistics between time periods.
    """
    permission_classes = [IsAuthenticated]
    
    @method_decorator(cache_page(60 * 10))  # Cache for 10 minutes
    @method_decorator(ratelimit(key='user', rate='30/m'))
    def get(self, request):
        """
        Handle GET requests for log comparison statistics.
        
        Compare current period log statistics with previous period.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with comparison data or error message
        """
        try:
            # Get query parameters
            days = int(request.query_params.get('days', 30))
            
            # Calculate date ranges
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            previous_start_date = start_date - timedelta(days=days)
            previous_end_date = end_date - timedelta(days=days)
            
            # Get comparison data
            comparison_data = LogAnalysisService.get_log_statistics_comparison(
                start_time=start_date,
                end_time=end_date,
                previous_start_time=previous_start_date,
                previous_end_time=previous_end_date
            )
            
            return Response(comparison_data)
        
        except Exception as e:
            logger.error(f"Failed to fetch log comparison: {str(e)}", exc_info=True)
            return Response(
                {"error": f"Failed to fetch log comparison: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def log_trends(request):
    """
    Get log volume trends over time with adjustable intervals.
    
    Args:
        request: HTTP request object
        
    Returns:
        Response with trend data or error message
    """
    try:
        # Get query parameters
        days = int(request.query_params.get('days', 30))
        interval = request.query_params.get('interval', 'day')
        
        # Validate interval
        valid_intervals = ['hour', 'day', 'week', 'month']
        if interval not in valid_intervals:
            return Response(
                {"error": f"Invalid interval. Choose from: {', '.join(valid_intervals)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Get trend data
        trend_data = LogAnalysisService.get_log_volume_by_timeframe(
            start_time=start_date,
            end_time=end_date,
            interval=interval
        )
        
        return Response({
            "trend_data": trend_data,
            "time_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": days,
                "interval": interval
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch log trends: {str(e)}", exc_info=True)
        return Response(
            {"error": f"Failed to fetch log trends: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )