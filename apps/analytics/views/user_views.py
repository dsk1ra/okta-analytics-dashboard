"""
Views for handling Okta user data and displaying user dashboard.

This module contains views for user management and analytics.
"""
from django.views.generic import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from apps.analytics.services.user_statistics import UserStatisticsService

import logging

logger = logging.getLogger(__name__)


@method_decorator(cache_page(60 * 5), name='dispatch')  # Cache entire view for 5 minutes
class UserDashboardView(LoginRequiredMixin, ListView):
    """
    View for displaying user analytics dashboard.
    Shows user activity, risk scores, and authentication patterns.
    """
    template_name = 'traffic_analysis/users/user_dashboard.html'
    context_object_name = 'users'
    paginate_by = 20
    login_url = '/login/'
    
    def get_queryset(self):
        """Get list of users from MongoDB"""
        # Get time range from query parameters (default to 30 days)
        days = int(self.request.GET.get('days', 30))
        
        # Get user statistics from service
        user_service = UserStatisticsService()
        stats = user_service.get_user_statistics(days=days)
        
        # Return the list of users for pagination
        return stats.get('recent_users', [])
    
    def get_context_data(self, **kwargs):
        """Add user statistics to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Get time range from query parameters (default to 30 days)
        days = int(self.request.GET.get('days', 30))
        
        # Get user statistics from service
        user_service = UserStatisticsService()
        stats = user_service.get_user_statistics(days=days)
        
        # Add threshold date for active status check
        from datetime import datetime, timedelta, timezone
        context['seven_days_ago'] = datetime.now(timezone.utc) - timedelta(days=7)
        
        # Convert lastActivity strings to datetime objects for template filtering
        for user in context['users']:
            if 'lastActivity' in user and isinstance(user['lastActivity'], str):
                try:
                    user['lastActivity'] = datetime.fromisoformat(user['lastActivity'].replace('Z', '+00:00'))
                except:
                    user['lastActivity'] = datetime.now(timezone.utc)
        
        # Add statistics to context (exclude recent_users since it's now in page_obj)
        context['total_users'] = stats.get('total_users', 0)
        context['active_users'] = stats.get('active_users', 0)
        context['inactive_users'] = stats.get('inactive_users', 0)
        context['locked_accounts'] = stats.get('locked_accounts', 0)
        context['days'] = days
        
        return context