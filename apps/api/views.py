import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.conf import settings
from django.shortcuts import render
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from core.services.okta_client import OktaApiClient
from apps.analytics.services.forensic_events import ForensicEventsService as ForensicEventsAnalyzer
from apps.analytics.services.event_simulation import OktaEventSimulator
from apps.api.serializers import (
    ForensicTimelineSerializer, ForensicSessionsSerializer,
    GeographicAnalysisSerializer, MfaUsageSerializer,
    ZeroTrustMetricsSerializer
)

logger = logging.getLogger(__name__)

# Initialize services
okta_client = OktaApiClient()
analyzer = ForensicEventsAnalyzer()
simulator = OktaEventSimulator()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def forensic_timeline(request: Request) -> Response:
    """
    Get forensic timeline of events with risk assessment
    
    Query Parameters:
    - start_date: ISO format date for filtering (YYYY-MM-DD)
    - end_date: ISO format date for filtering (YYYY-MM-DD)
    - user_id: Filter by Okta user ID
    - ip_address: Filter by IP address
    - simulate: If true, use simulated data (for testing)
    """
    try:
        # Extract query parameters
        filters = _get_filters_from_request(request)
        use_simulation = request.query_params.get('simulate', 'false').lower() == 'true'
        
        # Get events
        events = _get_events(use_simulation, filters)
        analyzer.set_events(events)
        
        # Generate timeline
        timeline = analyzer.get_timeline(filters)
        
        # Serialize and return
        serializer = ForensicTimelineSerializer(timeline)
        return Response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error generating forensic timeline: {e}")
        return Response(
            {"error": f"Failed to generate timeline: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def forensic_sessions(request: Request) -> Response:
    """
    Get forensic analysis of session chains
    
    Query Parameters:
    - start_date: ISO format date for filtering (YYYY-MM-DD)
    - end_date: ISO format date for filtering (YYYY-MM-DD)
    - user_id: Filter by Okta user ID
    - ip_address: Filter by IP address
    - simulate: If true, use simulated data (for testing)
    """
    try:
        # Extract query parameters
        filters = _get_filters_from_request(request)
        use_simulation = request.query_params.get('simulate', 'false').lower() == 'true'
        
        # Get events
        events = _get_events(use_simulation, filters)
        analyzer.set_events(events)
        
        # Generate session chains
        sessions = analyzer.get_session_chains(filters)
        
        # Serialize and return
        serializer = ForensicSessionsSerializer(sessions)
        return Response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error generating forensic sessions: {e}")
        return Response(
            {"error": f"Failed to analyze sessions: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def geographic_analysis(request: Request) -> Response:
    """
    Get geographic analysis of authentication events
    
    Query Parameters:
    - start_date: ISO format date for filtering (YYYY-MM-DD)
    - end_date: ISO format date for filtering (YYYY-MM-DD)
    - user_id: Filter by Okta user ID
    - simulate: If true, use simulated data (for testing)
    """
    try:
        # Extract query parameters
        filters = _get_filters_from_request(request)
        use_simulation = request.query_params.get('simulate', 'false').lower() == 'true'
        
        # Get events
        events = _get_events(use_simulation, filters)
        analyzer.set_events(events)
        
        # Analyze geographic movements
        movements = analyzer.analyze_geographic_movements(filters)
        
        # Serialize and return
        serializer = GeographicAnalysisSerializer(movements)
        return Response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error analyzing geographic movements: {e}")
        return Response(
            {"error": f"Failed to analyze geographic movements: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_usage(request: Request) -> Response:
    """
    Get analysis of MFA usage patterns
    
    Query Parameters:
    - start_date: ISO format date for filtering (YYYY-MM-DD)
    - end_date: ISO format date for filtering (YYYY-MM-DD)
    - user_id: Filter by Okta user ID
    - simulate: If true, use simulated data (for testing)
    """
    try:
        # Extract query parameters
        filters = _get_filters_from_request(request)
        use_simulation = request.query_params.get('simulate', 'false').lower() == 'true'
        
        # Get events
        events = _get_events(use_simulation, filters)
        analyzer.set_events(events)
        
        # Analyze MFA usage
        mfa_analysis = analyzer.analyze_mfa_usage(filters)
        
        # Serialize and return
        serializer = MfaUsageSerializer(mfa_analysis)
        return Response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error analyzing MFA usage: {e}")
        return Response(
            {"error": f"Failed to analyze MFA usage: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def zero_trust_metrics(request: Request) -> Response:
    """
    Get zero trust security metrics
    
    Query Parameters:
    - start_date: ISO format date for filtering (YYYY-MM-DD)
    - end_date: ISO format date for filtering (YYYY-MM-DD)
    - simulate: If true, use simulated data (for testing)
    """
    try:
        # Extract query parameters
        filters = _get_filters_from_request(request)
        use_simulation = request.query_params.get('simulate', 'false').lower() == 'true'
        
        # Get events for analysis
        events = _get_events(use_simulation, filters)
        analyzer.set_events(events)
        
        # Get session and MFA data for metrics
        sessions = analyzer.get_session_chains(filters)
        mfa_analysis = analyzer.analyze_mfa_usage(filters)
        movements = analyzer.analyze_geographic_movements(filters)
        
        # Calculate zero trust metrics
        metrics = {
            'start_date': filters.get('start_date', ''),
            'end_date': filters.get('end_date', ''),
            'mfa_usage_percentage': _calculate_mfa_percentage(events),
            'failed_login_percentage': _calculate_failed_login_percentage(events),
            'risk_score': _calculate_risk_score(events),
            'session_anomaly_count': sessions.get('suspicious_sessions', 0),
            'suspicious_ip_count': movements.get('movement_count', 0),
        }
        
        # Serialize and return
        serializer = ZeroTrustMetricsSerializer(metrics)
        return Response(serializer.data)
    
    except Exception as e:
        logger.exception(f"Error calculating zero trust metrics: {e}")
        return Response(
            {"error": f"Failed to calculate zero trust metrics: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_simulation(request: Request) -> Response:
    """
    Generate a simulation dataset
    
    Request body:
    {
        "num_sessions": 5,
        "include_suspicious": true,
        "include_impossible_travel": true,
        "include_mfa_comparison": true,
        "filename": "simulation.json"
    }
    """
    try:
        # Get simulation parameters
        num_sessions = request.data.get('num_sessions', 5)
        include_suspicious = request.data.get('include_suspicious', True)
        include_impossible_travel = request.data.get('include_impossible_travel', True)
        include_mfa_comparison = request.data.get('include_mfa_comparison', True)
        filename = request.data.get('filename', 'simulation.json')
        
        # Generate simulation
        events = simulator.generate_dataset(
            num_sessions=num_sessions,
            include_suspicious=include_suspicious,
            include_impossible_travel=include_impossible_travel,
            include_mfa_comparison=include_mfa_comparison
        )
        
        # Save to file if requested
        if filename:
            simulator.save_to_file(events, filename)
        
        return Response({
            "success": True,
            "event_count": len(events),
            "message": f"Generated {len(events)} simulated events"
        })
    
    except Exception as e:
        logger.exception(f"Error generating simulation: {e}")
        return Response(
            {"error": f"Failed to generate simulation: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Helper functions
def _get_filters_from_request(request: Request) -> Dict[str, Any]:
    """Extract filters from request parameters"""
    filters = {}
    
    # Date filtering
    if 'start_date' in request.query_params:
        filters['start_date'] = request.query_params['start_date']
        
    if 'end_date' in request.query_params:
        filters['end_date'] = request.query_params['end_date']
    
    # User filtering
    if 'user_id' in request.query_params:
        filters['user_id'] = request.query_params['user_id']
    
    # IP address filtering
    if 'ip_address' in request.query_params:
        filters['ip_address'] = request.query_params['ip_address']
    
    return filters


def _get_events(use_simulation: bool, filters: Dict[str, Any]) -> List[Dict]:
    """Get events from Okta API or simulation based on parameters"""
    # Initialize date parameters
    since = None
    until = None
    
    # Process date filters with proper error handling
    if 'start_date' in filters:
        try:
            # Convert to proper ISO format if needed
            since = filters['start_date']
            if not since.endswith('Z') and '+' not in since:
                since = f"{since}T00:00:00Z"
        except Exception as e:
            logger.warning(f"Invalid start_date format: {e}")
    
    if 'end_date' in filters:
        try:
            # Convert to proper ISO format if needed
            until = filters['end_date'] 
            if not until.endswith('Z') and '+' not in until:
                until = f"{until}T23:59:59Z"
        except Exception as e:
            logger.warning(f"Invalid end_date format: {e}")
    
    # If use_simulation is enabled and we're in DEBUG mode, use simulated data
    if use_simulation and settings.DEBUG:
        logger.info("Using simulated event data")
        return simulator.get_simulation_data(
            since=since, 
            until=until,
            user_id=filters.get('user_id'),
            ip_address=filters.get('ip_address')
        )
    
    # Otherwise use Okta API to get events from MongoDB
    return okta_client.get_security_events(
        since=since,
        until=until,
        user_id=filters.get('user_id'),
        ip_address=filters.get('ip_address'),
        limit=1000  # Get a reasonable number of events
    )


def _calculate_mfa_percentage(events: List[Dict]) -> float:
    """Calculate percentage of logins using MFA"""
    authentication_events = [e for e in events if _is_auth_event(e)]
    
    if not authentication_events:
        return 0
    
    mfa_events = [e for e in authentication_events if _event_used_mfa(e)]
    return round((len(mfa_events) / len(authentication_events)) * 100, 2)


def _calculate_failed_login_percentage(events: List[Dict]) -> float:
    """Calculate percentage of failed logins"""
    authentication_events = [e for e in events if _is_auth_event(e)]
    
    if not authentication_events:
        return 0
    
    failed_events = [
        e for e in authentication_events 
        if e.get('outcome', {}).get('result') == 'FAILURE'
    ]
    
    return round((len(failed_events) / len(authentication_events)) * 100, 2)


def _calculate_risk_score(events: List[Dict]) -> float:
    """Calculate a risk score based on various factors"""
    if not events:
        return 0
    
    # Initialize base risk
    risk_score = 50  # Start at medium risk
    
    # Count various factors
    auth_events = [e for e in events if _is_auth_event(e)]
    failed_auth = [e for e in auth_events if e.get('outcome', {}).get('result') == 'FAILURE']
    mfa_events = [e for e in auth_events if _event_used_mfa(e)]
    suspicious_locations = [e for e in events if e.get('location', {}).get('suspicious')]
    password_changes = [e for e in events if 'user.account.update_password' in e.get('event_type', '')]
    
    # Adjust risk based on factors
    if auth_events:
        failed_ratio = len(failed_auth) / len(auth_events)
        risk_score += failed_ratio * 20  # Up to 20 points for high failure rate
        
        mfa_ratio = len(mfa_events) / len(auth_events)
        risk_score -= mfa_ratio * 15  # Up to 15 points reduction for MFA usage
    
    if suspicious_locations:
        risk_score += len(suspicious_locations) * 5  # 5 points per suspicious location
    
    if password_changes:
        risk_score += len(password_changes) * 3  # 3 points per password change
    
    # Ensure score is between 0-100
    return round(max(0, min(100, risk_score)), 2)


def _is_auth_event(event: Dict) -> bool:
    """Check if an event is an authentication event"""
    auth_types = [
        'user.authentication',
        'user.session.start',
        'user.mfa',
        'user.login'
    ]
    return any(auth_type in event.get('event_type', '') for auth_type in auth_types)


def _event_used_mfa(event: Dict) -> bool:
    """Check if an event used MFA"""
    # Explicit MFA events
    if 'user.mfa' in event.get('event_type', ''):
        return True
        
    # Check authentication context
    auth_context = event.get('authentication_context', {})
    if auth_context.get('authentication_step') == 2:
        return True
        
    return False