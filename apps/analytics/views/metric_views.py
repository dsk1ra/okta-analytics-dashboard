"""
Views for displaying metrics and analytics about Okta activity.

This module contains views for metrics visualizations and trend analysis.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.http import JsonResponse
from django.views import View
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django_ratelimit.decorators import ratelimit

from apps.analytics.services.login_statistics import get_login_events_count, get_failed_login_count, get_security_events_count, get_total_events_count
from apps.analytics.services.metrics_service import get_metrics_data, get_auth_success_rate, get_mfa_usage_rate, get_avg_session_time, get_peak_usage_hour
from core.services.database import DatabaseService

import logging
import json
import datetime
from django.conf import settings

logger = logging.getLogger(__name__)


class MetricsDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying advanced metrics and analytics.
    Shows usage patterns, authentication statistics, and security metrics.
    """
    template_name = 'traffic_analysis/metrics/metrics_dashboard.html'
    login_url = '/login/'
    
    def get(self, request, *args, **kwargs):
        """Handle GET requests: instantiate a template response"""
        return super().get(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        """Add metrics data to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        try:
            # Get the days parameter from query string with default of 30
            days = self.request.GET.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            logger.info(f"Fetching metrics data for {days} days")
            
            # Connect directly to MongoDB like in event_views.py
            db_service = DatabaseService()
            db_name = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
            collection = db_service.get_collection(db_name, 'okta_logs')
            
            # Calculate the date threshold
            now = datetime.datetime.now(datetime.timezone.utc)
            threshold_date = now - datetime.timedelta(days=days)
            threshold_date_str = threshold_date.isoformat()
            
            # Check if we can access the database
            doc_count = collection.count_documents({})
            logger.info(f"Found {doc_count} total documents in the collection")
            
            # Get metrics data
            metrics = get_metrics_data(days)
            
            # Compute top items for template rendering
            auth_methods_top = sorted(metrics.get('auth_methods', {}).items(), key=lambda kv: kv[1], reverse=True)[:3]
            usage_by_app_top = sorted(metrics.get('usage_by_app', {}).items(), key=lambda kv: kv[1], reverse=True)[:5]

            # Add metrics to the context
            context.update({
                'days': days,
                'auth_success_rate': metrics['auth_success_rate'],
                'mfa_usage_rate': metrics['mfa_usage_rate'],
                'avg_session_time': metrics['avg_session_time'],
                'peak_usage_hour': metrics['peak_usage_hour'],
                'usage_by_app': metrics['usage_by_app'],
                'usage_by_app_top': usage_by_app_top,
                'usage_by_location': metrics['usage_by_location'],
                'usage_by_city': metrics.get('usage_by_city', {}),
                'usage_by_device': metrics['usage_by_device'],
                'auth_methods': metrics['auth_methods'],
                'auth_methods_top': auth_methods_top,
                'auth_rate_change': metrics['auth_rate_change'],
                'mfa_rate_change': metrics['mfa_rate_change'],
                'session_time_change': metrics['session_time_change'],
                'usage_by_browser': metrics['usage_by_browser'],
                'usage_by_os': metrics['usage_by_os'],
                'auth_activity': metrics['auth_activity'],
                'hourly_activity': metrics['hourly_activity'],
                'failed_logins_count': metrics['failed_logins_count'],
                'failed_logins_change': metrics['failed_logins_change'],
                'geo_data': json.dumps(metrics['geo_data'])
            })
            
            logger.info("Metrics data successfully retrieved and added to context")
            
        except Exception as e:
            logger.error(f"Error retrieving metrics data: {str(e)}", exc_info=True)
            # Provide default values if there's an error
            # Build defaults
            default_usage_by_app = {f"App {i}": 0 for i in range(1, 6)}
            default_auth_methods = {"PASSWORD": 65, "OTP": 25, "SMS": 10}
            default_usage_by_app_top = sorted(default_usage_by_app.items(), key=lambda kv: kv[1], reverse=True)[:5]
            default_auth_methods_top = sorted(default_auth_methods.items(), key=lambda kv: kv[1], reverse=True)[:3]

            context.update({
                'auth_success_rate': 98.5,
                'mfa_usage_rate': 68.0,
                'avg_session_time': 35,
                'peak_usage_hour': 10,
                'usage_by_app': default_usage_by_app,
                'usage_by_app_top': default_usage_by_app_top,
                'usage_by_location': {"United States": 42, "United Kingdom": 13, "Germany": 8},
                'usage_by_city': {"Chicago": 85, "Paris": 72, "San Francisco": 68},
                'usage_by_device': {"Desktop": 58, "Mobile": 32, "Tablet": 6, "API": 4},
                'auth_methods': default_auth_methods,
                'auth_methods_top': default_auth_methods_top,
                'auth_rate_change': 1.2,
                'mfa_rate_change': 3.8,
                'session_time_change': -2.1,
                'usage_by_browser': {"Chrome": 45, "Safari": 25, "Firefox": 15, "Edge": 10, "Other": 5},
                'usage_by_os': {"Windows": 40, "macOS": 30, "iOS": 15, "Android": 10, "Linux": 5},
                'failed_logins_count': 254,
                'failed_logins_change': -5.7,
                'geo_data': json.dumps([
                    {"country": "United States", "city": "United States", "count": 42, "coordinates": {"lat": 37.0902, "lon": -95.7129}},
                    {"country": "United Kingdom", "city": "United Kingdom", "count": 13, "coordinates": {"lat": 55.3781, "lon": -3.4360}},
                    {"country": "Germany", "city": "Germany", "count": 8, "coordinates": {"lat": 51.1657, "lon": 10.4515}}
                ]),
                'auth_activity': {
                    "dates": json.dumps(["2025-04-05", "2025-04-06", "2025-04-07", "2025-04-08", "2025-04-09", "2025-04-10", "2025-04-11"]),
                    "success": json.dumps([320, 345, 375, 390, 320, 360, 398]),
                    "failure": json.dumps([18, 25, 23, 17, 28, 15, 21]),
                    "mfa": json.dumps([280, 302, 315, 340, 286, 322, 358])
                },
                'hourly_activity': {
                    "day_labels": json.dumps(["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]),
                    "matrix": json.dumps([[0]*24 for _ in range(7)])
                },
                'error': f"Failed to retrieve metrics data: {str(e)}"
            })
        
        return context


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def login_events_stats(request):
    """
    API endpoint for getting login events statistics.
    Returns the count of successful login events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_login_events_count(days)
        
        return Response({
            'login_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving login events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve login events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def failed_login_stats(request):
    """
    API endpoint for getting failed login statistics.
    Returns the count of failed login attempts from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_failed_login_count(days)
        
        return Response({
            'failed_login_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving failed login stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve failed login statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def security_events_stats(request):
    """
    API endpoint for getting security events statistics.
    Returns the count of security events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_security_events_count(days)
        
        return Response({
            'security_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving security events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve security events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def total_events_stats(request):
    """
    API endpoint for getting total events statistics.
    Returns the count of all events from the last 30 days.
    """
    try:
        days = int(request.query_params.get('days', 30))
        count = get_total_events_count(days)
        
        return Response({
            'total_events_count': count,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving total events stats: {str(e)}")
        return Response({
            'error': 'Failed to retrieve total events statistics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='GET', block=True)
@cache_page(60 * 5)  # Cache for 5 minutes
def auth_metrics_stats(request):
    """
    API endpoint for getting authentication metrics.
    Returns success rate, MFA usage, and session time statistics.
    """
    try:
        days = int(request.query_params.get('days', 30))
        
        # Get metrics from our services
        auth_success_rate = get_auth_success_rate(days)
        mfa_usage_rate = get_mfa_usage_rate(days)
        avg_session_time = get_avg_session_time(days)
        peak_usage_hour = get_peak_usage_hour(days)
        
        return Response({
            'auth_success_rate': auth_success_rate,
            'mfa_usage_rate': mfa_usage_rate,
            'avg_session_time': avg_session_time,
            'peak_usage_hour': peak_usage_hour,
            'period_days': days
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error retrieving authentication metrics: {str(e)}")
        return Response({
            'error': 'Failed to retrieve authentication metrics',
            'detail': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)