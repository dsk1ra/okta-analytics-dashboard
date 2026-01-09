"""
Views for managing application settings and preferences.

This module contains views for configuration management and user preferences.
"""
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

import logging

logger = logging.getLogger(__name__)


class SettingsDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying and managing application settings.
    Shows configuration options, integration settings, and user preferences.
    """
    template_name = 'traffic_analysis/settings/settings_dashboard.html'
    login_url = '/login/'
    
    def dispatch(self, request, *args, **kwargs):
        # Store request in the instance for later use in get_context_data
        self.request = request
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        """Add settings data to context for dashboard display"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Add sample data for initial template rendering
        # In a real implementation, these would be fetched from services
        context.update({
            'integration_status': True,
            'last_sync_time': '2025-04-30T15:30:45Z',
            'retention_period_days': 90,
            'notification_email': 'admin@example.com',
            'api_rate_limit': 5000,
            'available_themes': [
                {'id': 'light', 'name': 'Light Theme'},
                {'id': 'dark', 'name': 'Dark Theme'},
                {'id': 'auto', 'name': 'System Default'}
            ],
            'current_theme': 'light',
            'webhook_configured': True
        })
        
        return context