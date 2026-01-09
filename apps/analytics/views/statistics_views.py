from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from apps.analytics.services.device_app_statistics import (
    get_device_statistics, 
    get_operating_system_statistics, 
    get_browser_statistics, 
    get_application_statistics,
    get_login_location_statistics,
    get_login_outcome_statistics,
    get_all_statistics,
)
from apps.analytics.serializers.statistics_serializers import (
    StatisticsSerializer,
    DeviceStatisticsSerializer,
    ApplicationStatisticsSerializer,
    BrowserStatisticsSerializer,
    OSStatisticsSerializer,
    LocationStatisticsSerializer,
    OutcomeStatisticsSerializer,
    AllStatisticsSerializer,
    EventActivitySerializer,
    EventDistributionSerializer,
    RecentEventsSerializer,
)
from apps.analytics.services.login_statistics import get_event_activity, get_event_distribution, get_recent_events
import logging

logger = logging.getLogger(__name__)

class DeviceStatisticsView(APIView):
    """
    API view for retrieving device statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get device statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get device statistics
            device_stats = get_device_statistics(days)
            
            # Serialize and return the data
            serializer = DeviceStatisticsSerializer(data={'devices': device_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in DeviceStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving device statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class BrowserStatisticsView(APIView):
    """
    API view for retrieving browser statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get browser statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get browser statistics
            browser_stats = get_browser_statistics(days)
            
            # Serialize and return the data
            serializer = BrowserStatisticsSerializer(data={'browsers': browser_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in BrowserStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving browser statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
class OSStatisticsView(APIView):
    """
    API view for retrieving operating system statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get operating system statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get OS statistics
            os_stats = get_operating_system_statistics(days)
            
            # Serialize and return the data
            serializer = OSStatisticsSerializer(data={'operating_systems': os_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in OSStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving OS statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ApplicationStatisticsView(APIView):
    """
    API view for retrieving application statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get application statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get application statistics
            app_stats = get_application_statistics(days)
            
            # Serialize and return the data
            serializer = ApplicationStatisticsSerializer(data={'applications': app_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in ApplicationStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving application statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class LocationStatisticsView(APIView):
    """
    API view for retrieving location statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get location (country) statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get location statistics
            location_stats = get_login_location_statistics(days)
            
            # Serialize and return the data
            serializer = LocationStatisticsSerializer(data={'locations': location_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in LocationStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving location statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
class OutcomeStatisticsView(APIView):
    """
    API view for retrieving login outcome statistics
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get login outcome statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get outcome statistics
            outcome_stats = get_login_outcome_statistics(days)
            
            # Serialize and return the data
            serializer = OutcomeStatisticsSerializer(data={'outcomes': outcome_stats})
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in OutcomeStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving outcome statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventActivityStatisticsView(APIView):
    """Time-series event activity for configurable windows (7/14/30 days)."""
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            days_param = request.query_params.get('days', '7')
            try:
                days = int(days_param)
            except (TypeError, ValueError):
                days = 7

            # Only allow common UI windows; clamp otherwise
            if days not in (7, 14, 30):
                days = max(1, min(365, days))

            data = get_event_activity(days)
            serializer = EventActivitySerializer(data=data)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error in EventActivityStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving event activity."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EventDistributionStatisticsView(APIView):
    """Event type distribution for a configurable window."""
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            days_param = request.query_params.get('days', '30')
            try:
                days = int(days_param)
            except (TypeError, ValueError):
                days = 30

            days = max(1, min(365, days))
            data = get_event_distribution(days)
            serializer = EventDistributionSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error in EventDistributionStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving event distribution."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RecentEventsView(APIView):
    """Recent events with time filtering."""
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        try:
            limit = int(request.query_params.get('limit', '5'))
            hours = int(request.query_params.get('hours', '24'))
            
            events = get_recent_events(limit=limit, hours=hours)
            serializer = RecentEventsSerializer(data=events, many=True)
            serializer.is_valid(raise_exception=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error in RecentEventsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving recent events."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AllStatisticsView(APIView):
    """
    API view for retrieving all statistics at once
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        """Get all statistics for login events"""
        try:
            # Get the days parameter from query string with default of 30
            days = request.query_params.get('days', 30)
            
            # Convert days to integer, with a fallback to default
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 30
            
            # Cap days to reasonable limits
            days = max(1, min(365, days))
            
            # Get all statistics at once
            all_stats = get_all_statistics(days)
            
            # Serialize and return the data
            serializer = AllStatisticsSerializer(data=all_stats)
            serializer.is_valid(raise_exception=True)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Error in AllStatisticsView: {str(e)}", exc_info=True)
            return Response(
                {"error": "An error occurred while retrieving statistics."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )