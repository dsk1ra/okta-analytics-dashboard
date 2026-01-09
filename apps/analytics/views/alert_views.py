"""
Views for handling alerts and notifications in the Okta dashboard.

This module contains views for alert management and configuration.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.views.generic import ListView, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.conf import settings
from django.utils import timezone
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from core.services.database import DatabaseService
from apps.analytics.services.alert_statistics import AlertStatisticsService

import logging

logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination for alert listing endpoints.
    """
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100


class AlertDashboardView(LoginRequiredMixin, TemplateView):
    """
    View for displaying and filtering security alerts in a user-friendly UI.
    """
    template_name = 'traffic_analysis/alerts/alert_dashboard.html'
    login_url = '/login/'
    paginate_by = 10
    
    def get_context_data(self, **kwargs):
        """Add extra context data for template rendering"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request (set by SecurityHeadersMiddleware)
        # instead of generating a new one
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        # Get filter parameters
        days = int(self.request.GET.get('days', 7))
        
        # Get alert statistics from service
        alert_service = AlertStatisticsService()
        stats = alert_service.get_alert_statistics(days=days)
        
        # Add statistics to context
        context['total_alerts'] = stats.get('total_alerts', 0)
        context['critical_alerts'] = stats.get('critical_alerts', 0)
        context['high_alerts'] = stats.get('high_alerts', 0)
        context['medium_alerts'] = stats.get('medium_alerts', 0)
        context['low_alerts'] = stats.get('low_alerts', 0)
        context['days'] = days
        
        # Get available filter options
        context['available_alert_types'] = alert_service.get_alert_types()
        context['available_severities'] = ['critical', 'high', 'medium', 'low']
        
        # Handle pagination for alerts
        recent_alerts = stats.get('recent_alerts', [])
        paginator = Paginator(recent_alerts, self.paginate_by)
        page_number = self.request.GET.get('page', 1)
        
        try:
            page_obj = paginator.page(page_number)
        except PageNotAnInteger:
            page_obj = paginator.page(1)
        except EmptyPage:
            page_obj = paginator.page(paginator.num_pages)
        
        context['alerts'] = page_obj.object_list
        context['page_obj'] = page_obj
        context['is_paginated'] = page_obj.has_other_pages()
        
        return context


class AlertDetailPageView(LoginRequiredMixin, TemplateView):
    """
    View for displaying detailed information about a specific alert.
    """
    template_name = 'traffic_analysis/alerts/alert_detail.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        """Add context data for the alert detail page"""
        context = super().get_context_data(**kwargs)
        
        # Use the nonce from the request
        if hasattr(self.request, 'nonce'):
            context['nonce'] = self.request.nonce
        
        return context


class AlertListView(APIView):
    """
    API view for listing security alerts with filtering and pagination.
    """
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get(self, request):
        """
        Handle GET requests for alert listing.
        
        Supports filtering by time range, alert type, and severity.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with serialized alerts or error message
        """
        # Get filtering parameters from query string
        days = int(request.query_params.get('days', 7))
        alert_type = request.query_params.get('alert_type')
        severity = request.query_params.get('severity')
        
        # Calculate time range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        try:
            # Get page parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 25))
            
            # Build query filters
            query_filters = {
                "timestamp__gte": start_date,
                "timestamp__lte": end_date,
                "severity__in": ['critical', 'high'] if not severity else [severity]
            }
            
            if alert_type:
                query_filters["event_type"] = alert_type
            
            # Execute query with pagination
            skip = (page - 1) * page_size
            alerts = ForensicEvent.objects(**query_filters).order_by('-timestamp').skip(skip).limit(page_size)
            
            # Count total for pagination
            total_alerts = ForensicEvent.objects(**query_filters).count()
            total_pages = (total_alerts + page_size - 1) // page_size
            
            # Prepare result data manually since we're not using a serializer class
            alert_data = []
            for alert in alerts:
                alert_data.append({
                    'id': str(alert.id),
                    'event_id': alert.event_id,
                    'timestamp': alert.timestamp,
                    'event_type': alert.event_type,
                    'severity': alert.severity,
                    'username': alert.username,
                    'ip_address': alert.ip_address,
                    'resource': alert.resource,
                    'action': alert.action,
                    'status': alert.status,
                })
            
            # Construct paginated response
            result = {
                'count': total_alerts,
                'total_pages': total_pages,
                'current_page': page,
                'next': page + 1 if page < total_pages else None,
                'previous': page - 1 if page > 1 else None,
                'results': alert_data
            }
            
            return Response(result)
        
        except Exception as e:
            logger.error(f"Error in AlertListView: {str(e)}")
            return Response(
                {"error": f"Failed to fetch alerts: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AlertDetailView(APIView):
    """
    API view for retrieving details of a specific security alert.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, alert_id):
        """
        Handle GET request for a specific alert by ID.
        
        Args:
            request: HTTP request object
            alert_id: ID of the alert to retrieve (uuid)
            
        Returns:
            Response with alert data or error message
        """
        try:
            # Get MongoDB connection
            db_service = DatabaseService()
            collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
            
            # Find alert by uuid (the unique identifier in okta_logs)
            alert = collection.find_one({'uuid': alert_id})
            
            if not alert:
                return Response(
                    {"error": f"Alert with ID {alert_id} not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Extract actor and client info
            actor = alert.get('actor', {})
            client = alert.get('client', {})
            
            # Convert alert to dictionary for response
            alert_data = {
                'id': str(alert.get('_id')),
                'event_id': alert.get('uuid'),
                'timestamp': alert.get('published'),
                'event_type': alert.get('eventType', 'Unknown'),
                'severity': alert.get('severity', 'INFO'),
                'username': actor.get('alternateId', 'System') if isinstance(actor, dict) else 'System',
                'ip_address': client.get('ipAddress', 'N/A') if isinstance(client, dict) else 'N/A',
                'message': alert.get('displayMessage', ''),
                'status': alert.get('status', 'new'),
                'user_agent': client.get('userAgent', '') if isinstance(client, dict) else '',
                'resource': alert.get('target', {}).get('displayName', '') if isinstance(alert.get('target'), dict) else '',
                'context': alert.get('context', {})
            }
            
            return Response(alert_data)
            
        except Exception as e:
            logger.error(f"Error in AlertDetailView GET: {str(e)}")
            return Response(
                {"error": f"Failed to fetch alert details: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def post(self, request, alert_id):
        """
        Handle POST request to update alert status.
        
        Args:
            request: HTTP request object containing new status
            alert_id: ID of the alert to update (uuid)
            
        Returns:
            Response with updated alert data or error message
        """
        try:
            new_status = request.data.get('status')
            
            if not new_status:
                return Response(
                    {"error": "Status is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Valid statuses
            valid_statuses = ['new', 'investigating', 'resolved']
            if new_status not in valid_statuses:
                return Response(
                    {"error": f"Invalid status. Must be one of {valid_statuses}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get MongoDB connection and update alert
            db_service = DatabaseService()
            collection = db_service.get_collection('OktaDashboardDB', 'okta_logs')
            
            # Find and update the alert by uuid
            result = collection.update_one(
                {'uuid': alert_id},
                {'$set': {'status': new_status}}
            )
            
            if result.matched_count == 0:
                return Response(
                    {"error": f"Alert with ID {alert_id} not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Fetch the updated alert
            alert = collection.find_one({'uuid': alert_id})
            
            return Response({
                'id': str(alert.get('_id')),
                'event_id': alert.get('uuid'),
                'status': alert.get('status'),
                'message': f'Alert status updated to {new_status}'
            })
            
        except Exception as e:
            logger.error(f"Error updating alert status: {str(e)}")
            return Response(
                {"error": f"Failed to update alert: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )