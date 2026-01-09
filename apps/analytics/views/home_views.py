"""
Home views for the traffic analysis dashboard.

This module contains the views for the landing page and other public-facing pages.
"""
import logging
from datetime import datetime, timedelta
from django.shortcuts import render
from django.views.generic import View, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.conf import settings

from apps.analytics.models import OktaEvent, OktaMetrics
from apps.analytics.services.login_statistics import (
    get_login_events_count, 
    get_failed_login_count, 
    get_security_events_count, 
    get_total_events_count,
    get_total_events_with_comparison,
    get_login_events_with_comparison,
    get_failed_login_with_comparison,
    get_security_events_with_comparison,
    get_event_activity,
    get_event_distribution,
)
from apps.monitoring.utils import get_avg_login_time_with_comparison
from core.services.database import DatabaseService

logger = logging.getLogger(__name__)

# Simple function-based view for the home page to avoid async/sync issues
def home_page_view(request):
    """
    Simple function-based view for the home page.
    This avoids any async/sync compatibility issues.
    """
    # Set device trust level to 1 to avoid high risk in ContinuousAuthMiddleware
    if request.user.is_authenticated:
        request.session['device_trust_level'] = 1
    return render(request, 'traffic_analysis/landing_page.html')

# Legacy class-based view, kept for reference but not used
class HomePageView(TemplateView):
    template_name = 'traffic_analysis/landing_page.html'

class DashboardHomeView(LoginRequiredMixin, TemplateView):
    template_name = 'traffic_analysis/dashboard/index.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        # Set device trust level to 1 to avoid high risk in ContinuousAuthMiddleware
        if self.request.user.is_authenticated:
            self.request.session['device_trust_level'] = 1
        context = super().get_context_data(**kwargs)
        
        # Use the DatabaseService singleton for MongoDB connection
        try:
            # Get the database service instance
            db_service = DatabaseService()
            
            if not db_service.is_connected():
                logger.warning("Database not connected. Attempting to reconnect...")
                db_service.connect()
            
            # Get MongoDB client
            client = db_service.get_client()
            mongo_db = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
            db = client[mongo_db]
            # Use the raw Okta logs collection
            events_collection = db.okta_logs
            
            # Log connection status
            logger.info(f"MongoDB connection status: {db_service.is_connected()}")
            
            # Calculate time ranges
            now = timezone.now()
            thirty_days_ago = now - timedelta(days=30)
            seven_days_ago = now - timedelta(days=7)
            
            # Get total count of events using our improved statistics service
            events_comparison = get_total_events_with_comparison(current_days=30, previous_days=30)
            context['total_events'] = events_comparison['current_count']
            context['total_events_previous'] = events_comparison['previous_count']
            context['total_events_change'] = events_comparison['percent_change']
            logger.info(f"Total events: {context['total_events']}, Previous: {context['total_events_previous']}, Change: {context['total_events_change']}%")
            
            # Get login events count using our improved statistics service
            login_comparison = get_login_events_with_comparison(current_days=30, previous_days=30)
            context['login_events'] = login_comparison['current_count']
            context['login_events_previous'] = login_comparison['previous_count']
            context['login_events_change'] = login_comparison['percent_change']
            logger.info(f"Login events: {context['login_events']}, Previous: {context['login_events_previous']}, Change: {context['login_events_change']}%")
            
            # Get failed login attempts using our improved statistics service
            failed_comparison = get_failed_login_with_comparison(current_days=30, previous_days=30)
            context['failed_events'] = failed_comparison['current_count']
            context['failed_events_previous'] = failed_comparison['previous_count']
            context['failed_events_change'] = failed_comparison['percent_change']
            logger.info(f"Failed login events: {context['failed_events']}, Previous: {context['failed_events_previous']}, Change: {context['failed_events_change']}%")
            
            # Get security events count using our improved statistics service
            security_comparison = get_security_events_with_comparison(current_days=30, previous_days=30)
            context['security_events'] = security_comparison['current_count']
            context['security_events_previous'] = security_comparison['previous_count']
            context['security_events_change'] = security_comparison['percent_change']
            logger.info(f"Security events: {context['security_events']}, Previous: {context['security_events_previous']}, Change: {context['security_events_change']}%")
            
            # Get average login time with comparison
            login_time_comparison = get_avg_login_time_with_comparison(current_days=1, previous_days=1)
            context['avg_login_time'] = login_time_comparison['current_avg']
            context['avg_login_time_previous'] = login_time_comparison['previous_avg']
            context['avg_login_time_change'] = login_time_comparison['percent_change']
            logger.info(f"Avg login time: {context['avg_login_time']}, Previous: {context['avg_login_time_previous']}ms, Change: {context['avg_login_time_change']}%")
                
            # Note: Recent events are now loaded via AJAX on the frontend
            # No need to pass recent_events in context
            
            # Prepare data for event activity chart using services (handles ISO date fields)
            activity = get_event_activity(days=7)
            chart_dates = activity['labels']
            successful_logins = activity['successful']
            failed_logins = activity['failed']
            security_events = activity['security']

            # Get event distribution using service
            distribution = get_event_distribution(days=30)
            distribution_labels = distribution['labels']
            distribution_data = distribution['counts']
            
            # Calculate metrics trends
            login_trend = 0
            failed_trend = 0
            security_trend = 0
            
            # Compare last 7 days to previous 7 days (use ISO strings on published and correct field names)
            seven_days_ago_iso = (now - timedelta(days=7)).isoformat() + 'Z'
            previous_period_start_dt = now - timedelta(days=14)
            previous_period_start_iso = previous_period_start_dt.isoformat() + 'Z'
            previous_period_end_iso = seven_days_ago_iso

            current_period_logins = events_collection.count_documents({
                'eventType': {'$regex': '(user\\.session\\.start|user\\.authentication\\.sso)'},
                'published': {'$gte': seven_days_ago_iso}
            })
            
            previous_period_logins = events_collection.count_documents({
                'eventType': {'$regex': '(user\\.session\\.start|user\\.authentication\\.sso)'},
                'published': {'$gte': previous_period_start_iso, '$lt': previous_period_end_iso}
            })
            
            if previous_period_logins > 0:
                login_trend = ((current_period_logins - previous_period_logins) / previous_period_logins) * 100
                
            # Calculate failed login trend
            current_period_failed = events_collection.count_documents({
                'eventType': {'$regex': 'user\\.authentication'},
                'outcome.result': 'FAILURE',
                'published': {'$gte': seven_days_ago_iso}
            })
            
            previous_period_failed = events_collection.count_documents({
                'eventType': {'$regex': 'user\\.authentication'},
                'outcome.result': 'FAILURE',
                'published': {'$gte': previous_period_start_iso, '$lt': previous_period_end_iso}
            })
            
            if previous_period_failed > 0:
                failed_trend = ((current_period_failed - previous_period_failed) / previous_period_failed) * 100
                
            # Calculate security events trend
            current_period_security = events_collection.count_documents({
                'eventType': {'$regex': '(security|threat)'},
                'published': {'$gte': seven_days_ago_iso}
            })
            
            previous_period_security = events_collection.count_documents({
                'eventType': {'$regex': '(security|threat)'},
                'published': {'$gte': previous_period_start_iso, '$lt': previous_period_end_iso}
            })
            
            if previous_period_security > 0:
                security_trend = ((current_period_security - previous_period_security) / previous_period_security) * 100

            # Add all data to context
            # Recent events are loaded via AJAX; ensure no undefined variable
            context['recent_events'] = []
            context['chart_dates'] = chart_dates
            context['successful_logins'] = successful_logins
            context['failed_logins'] = failed_logins
            context['security_events_chart'] = security_events
            context['distribution_labels'] = distribution_labels
            context['distribution_data'] = distribution_data
            context['login_trend'] = login_trend
            context['failed_trend'] = failed_trend
            context['security_trend'] = security_trend
            
            logger.info(f"Successfully loaded dashboard data with {context['total_events']} total events")
            
        except Exception as e:
            logger.error(f"Error fetching dashboard data from MongoDB: {str(e)}")
            context['error'] = "Could not fetch dashboard data from database"
            context['total_events'] = 0
            context['login_events'] = 0
            context['failed_events'] = 0
            context['security_events'] = 0
            context['recent_events'] = []
        
        return context