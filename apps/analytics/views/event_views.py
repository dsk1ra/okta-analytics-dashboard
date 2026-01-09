"""
Views for handling Okta event data requests.

This module contains API view classes for querying and displaying Okta event data.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination

from apps.analytics.models import OktaEvent, OktaMetrics
from apps.analytics.serializers.event_serializers import (
    OktaEventSerializer,
    OktaEventDetailSerializer,
    OktaMetricsSerializer
)

import logging
from django.views.generic import ListView, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count, Q
from apps.analytics.services.event_service import EventService
from core.services.database import DatabaseService  # Updated import path
from django.conf import settings

logger = logging.getLogger(__name__)

class StandardResultsSetPagination(PageNumberPagination):
    """
    Standard pagination for event listing endpoints.
    """
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100


class EventsPageView(LoginRequiredMixin, ListView):
    """
    View for displaying and filtering Okta events in a user-friendly UI.
    This view uses the same data as the API endpoints but renders HTML templates.
    """
    template_name = 'traffic_analysis/events/events_list.html'
    context_object_name = 'events'
    paginate_by = 20
    login_url = '/login/'
    
    def get_queryset(self):
        """Get filtered events based on request parameters"""
        # Get filter parameters
        event_type = self.request.GET.get('event_type', '')
        severity = self.request.GET.get('severity', '')
        days = int(self.request.GET.get('days', 7))
        search = self.request.GET.get('search', '')
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_date_iso = start_date.isoformat() + 'Z'  # MongoDB uses ISO format with Z
        
        # Connect to MongoDB
        db_service = DatabaseService()
        db_name = settings.MONGODB_SETTINGS.get('db', 'okta_dashboard')
        logs_collection = db_service.get_collection(db_name, 'okta_logs')
        
        # Base query with time range
        query = {'published': {'$gte': start_date_iso}}
        
        # Apply additional filters if provided
        if event_type:
            query['eventType'] = event_type
        
        if severity:
            query['severity'] = severity
        
        if search:
            # For text search we need to use $or with different fields
            query['$or'] = [
                {'eventType': {'$regex': search, '$options': 'i'}},
                {'displayMessage': {'$regex': search, '$options': 'i'}},
                {'client.ipAddress': {'$regex': search, '$options': 'i'}}
            ]
        
        # Execute query, sort by published date descending
        cursor = logs_collection.find(query).sort('published', -1)
        
        # Convert MongoDB documents to a list of dictionaries
        events = list(cursor)
        
        # Process and transform each event document to match template expectations
        for event in events:
            # Extract IP address from client field if it exists
            if 'client' in event and event['client'] and 'ipAddress' in event['client']:
                event['ip_address'] = event['client']['ipAddress']
            else:
                event['ip_address'] = 'N/A'
            
            # Format the published date
            if 'published' in event:
                try:
                    # Parse ISO format timestamp
                    timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
                    event['published_formatted'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    logger.error(f"Error formatting date: {e}")
                    event['published_formatted'] = event['published']
            
            # Ensure actor related fields are properly accessible
            if 'actor' in event:
                if 'alternateId' in event['actor'] and 'alternate_id' not in event['actor']:
                    event['actor']['alternate_id'] = event['actor']['alternateId']
                if 'displayName' in event['actor'] and 'display_name' not in event['actor']:
                    event['actor']['display_name'] = event['actor']['displayName']
            
            # Ensure displayMessage is accessible as display_message
            if 'displayMessage' in event and 'display_message' not in event:
                event['display_message'] = event['displayMessage']
            
            # Transform target array into individual target objects
            if 'target' in event and isinstance(event['target'], list):
                for i, target in enumerate(event['target']):
                    target_key = f'target{i}'
                    event[target_key] = target
                    # Map camelCase to snake_case for target fields
                    if 'alternateId' in target and 'alternate_id' not in target:
                        event[target_key]['alternate_id'] = target['alternateId']
                    if 'displayName' in target and 'display_name' not in target:
                        event[target_key]['display_name'] = target['displayName']
            
            # Ensure client fields are properly mapped
            if 'client' in event and event['client']:
                if 'geographicalContext' in event['client'] and 'geographical_context' not in event['client']:
                    event['client']['geographical_context'] = event['client']['geographicalContext']
                if 'userAgent' in event['client'] and 'user_agent' not in event['client']:
                    event['client']['user_agent'] = event['client']['userAgent']
        
        return events
    
    def get_context_data(self, **kwargs):
        """Add extra context data for template rendering"""
        context = super().get_context_data(**kwargs)
        
        # Get filter parameters to add to context
        context['selected_event_type'] = self.request.GET.get('event_type', '')
        context['selected_severity'] = self.request.GET.get('severity', '')
        context['days'] = int(self.request.GET.get('days', 7))
        context['search_query'] = self.request.GET.get('search', '')
        context['date_range_days'] = context['days']
        
        # Add statistics for the filter results
        queryset = self.get_queryset()
        context['total_events'] = len(queryset)
        context['high_severity_count'] = len([event for event in queryset if event.get('severity') == 'HIGH'])
        context['medium_severity_count'] = len([event for event in queryset if event.get('severity') == 'MEDIUM'])
        context['low_severity_count'] = len([event for event in queryset if event.get('severity') == 'LOW'])
        
        # Get available filter options
        service = EventService()
        context['available_event_types'] = service.get_event_types()
        context['available_severities'] = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        return context


class EventListView(APIView):
    """
    API view for listing Okta events with filtering and pagination.
    """
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get(self, request):
        """
        Handle GET requests for event listing.
        
        Supports filtering by time range, event type, and severity.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with serialized events or error message
        """
        # Get filtering parameters from query string
        days = int(request.query_params.get('days', 7))
        event_type = request.query_params.get('event_type')
        severity = request.query_params.get('severity')
        ip_address = request.query_params.get('ip_address')
        
        # Calculate time range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        try:
            # Get page parameters
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 25))
            
            # Use the optimized method from the model instead of direct query
            events = OktaEvent.get_events_by_timeframe(
                start_time=start_date,
                end_time=end_date,
                event_type=event_type,
                limit=page_size,
                page=page
            )
            
            # Get total count for pagination
            # Build query filter for count
            query_filters = {
                "published__gte": start_date,
                "published__lte": end_date,
            }
            
            if event_type:
                query_filters["event_type"] = event_type
            
            if severity:
                query_filters["severity"] = severity
            
            if ip_address:
                query_filters["ip_address"] = ip_address
                
            total_events = OktaEvent.objects(**query_filters).count()
            total_pages = (total_events + page_size - 1) // page_size
            
            # Serialize data
            serializer = OktaEventSerializer(events, many=True)
            
            # Construct paginated response
            result = {
                'count': total_events,
                'total_pages': total_pages,
                'current_page': page,
                'next': page + 1 if page < total_pages else None,
                'previous': page - 1 if page > 1 else None,
                'results': serializer.data
            }
            
            return Response(result)
        
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch events: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventDetailView(LoginRequiredMixin, TemplateView):
    """
    View for displaying detailed information about a specific Okta event.
    """
    template_name = 'traffic_analysis/events/detail/event_detail.html'
    login_url = '/login/'
    
    def get_context_data(self, **kwargs):
        """Add event data to the template context"""
        context = super().get_context_data(**kwargs)
        
        # Get event ID from URL
        event_id = self.kwargs.get('event_id')
        
        # Connect to MongoDB
        db_service = DatabaseService()
        db_name = settings.MONGODB_SETTINGS.get('db', 'okta_dashboard')
        logs_collection = db_service.get_collection(db_name, 'okta_logs')
        
        # Find event by UUID
        event = logs_collection.find_one({'uuid': event_id})
        
        if not event:
            # Handle case where event is not found
            context['error'] = f"Event with ID {event_id} not found"
            return context
        
        # Process event document to make it template-friendly
        self._process_event_document(event)
        
        # Add event to context
        context['event'] = event
        
        # Add serialized JSON for raw data view
        import json
        from bson import json_util
        context['event_json'] = json.dumps(event, indent=2, default=json_util.default)
        
        return context
    
    def _process_event_document(self, event):
        """
        Process and transform the event document to match template expectations.
        This mirrors the processing done in the EventsPageView class.
        """
        # Extract IP address from client field if it exists
        if 'client' in event and event['client'] and 'ipAddress' in event['client']:
            event['ip_address'] = event['client']['ipAddress']
        else:
            event['ip_address'] = 'N/A'
        
        # Format the published date
        if 'published' in event:
            try:
                # Parse ISO format timestamp
                timestamp = datetime.fromisoformat(event['published'].replace('Z', '+00:00'))
                event['published_formatted'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                logger.error(f"Error formatting date: {e}")
                event['published_formatted'] = event['published']
        
        # Ensure actor related fields are properly accessible
        if 'actor' in event:
            if 'alternateId' in event['actor'] and 'alternate_id' not in event['actor']:
                event['actor']['alternate_id'] = event['actor']['alternateId']
            if 'displayName' in event['actor'] and 'display_name' not in event['actor']:
                event['actor']['display_name'] = event['actor']['displayName']
        
        # Ensure displayMessage is accessible as display_message
        if 'displayMessage' in event and 'display_message' not in event:
            event['display_message'] = event['displayMessage']
        
        # Transform target array into individual target objects
        if 'target' in event and isinstance(event['target'], list):
            for i, target in enumerate(event['target']):
                target_key = f'target{i}'
                event[target_key] = target
                # Map camelCase to snake_case for target fields
                if 'alternateId' in target and 'alternate_id' not in target:
                    event[target_key]['alternate_id'] = target['alternateId']
                if 'displayName' in target and 'display_name' not in target:
                    event[target_key]['display_name'] = target['displayName']
        
        # Ensure client fields are properly mapped
        if 'client' in event and event['client']:
            if 'geographicalContext' in event['client'] and 'geographical_context' not in event['client']:
                event['client']['geographical_context'] = event['client']['geographicalContext']
            if 'userAgent' in event['client'] and 'user_agent' not in event['client']:
                event['client']['user_agent'] = event['client']['userAgent']


class EventMetricsView(APIView):
    """
    API view for retrieving aggregated event metrics.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Handle GET request for event metrics.
        
        Supports filtering by time period and metric type.
        
        Args:
            request: HTTP request object
            
        Returns:
            Response with serialized metrics or error message
        """
        metric_type = request.query_params.get('metric_type', 'login_attempts')
        time_period = request.query_params.get('time_period', 'daily')
        limit = int(request.query_params.get('limit', 30))
        
        try:
            metrics = OktaMetrics.get_recent_metrics(
                metric_type=metric_type,
                time_period=time_period,
                limit=limit
            )
            
            serializer = OktaMetricsSerializer(metrics, many=True)
            return Response(serializer.data)
            
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch metrics: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )