"""
Service for calculating alert statistics from Okta logs.

This module provides functions to analyze security alerts and generate statistics
for the alert dashboard.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
from django.conf import settings
from django.core.cache import cache
from core.services.database import DatabaseService

CACHE_TIMEOUT = getattr(settings, "ANALYTICS_CACHE_TIMEOUT", 300)


class AlertStatisticsService:
    """Service for calculating alert statistics from MongoDB Okta logs"""
    
    def __init__(self):
        """Initialize the alert statistics service"""
        self.db_service = DatabaseService()
        self.collection = self.db_service.get_collection('OktaDashboardDB', 'okta_logs')
    
    def get_alert_statistics(self, days: int = 30) -> Dict[str, Any]:
        """
        Get alert statistics for the specified time period.
        
        Args:
            days: Number of days to analyze (default: 30)
            
        Returns:
            Dictionary containing alert statistics
        """
        # Skip cache and always recalculate to ensure fresh data with proper datetime conversion
        # cache_key = f"alert_stats:{days}"
        # cached = cache.get(cache_key)
        # if cached is not None:
        #     return cached

        # Calculate time range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        start_date_iso = start_date.isoformat().replace('+00:00', 'Z')
        
        # Map Okta severity levels to alert severity
        # WARN -> high, ERROR -> critical, INFO with specific patterns -> medium
        severity_mapping = {
            'WARN': 'high',
            'ERROR': 'critical'
        }
        
        # Base query for time range
        base_query = {'published': {'$gte': start_date_iso}}
        
        # Get total alerts (WARN and ERROR events)
        total_alerts = self.collection.count_documents({
            **base_query,
            'severity': {'$in': ['WARN', 'ERROR']}
        })
        
        # Get critical alerts (ERROR severity)
        critical_alerts = self.collection.count_documents({
            **base_query,
            'severity': 'ERROR'
        })
        
        # Get high alerts (WARN severity)
        high_alerts = self.collection.count_documents({
            **base_query,
            'severity': 'WARN'
        })
        
        # For medium alerts, look for failed auth with INFO
        medium_alerts = self.collection.count_documents({
            **base_query,
            'severity': 'INFO',
            'displayMessage': {'$regex': 'fail|deny|reject', '$options': 'i'}
        })
        
        # Low alerts - other INFO events that might be concerning
        low_alerts = self.collection.count_documents({
            **base_query,
            'severity': 'INFO',
            'eventType': {'$in': ['user.session.end', 'policy.rule.deactivate']}
        })
        
        # Get recent alerts (last 20)
        recent_alerts_cursor = self.collection.find({
            **base_query,
            'severity': {'$in': ['WARN', 'ERROR']}
        }).sort('published', -1).limit(20)
        
        recent_alerts = []
        for alert in recent_alerts_cursor:
            # Map to alert severity
            okta_severity = alert.get('severity', 'INFO')
            alert_severity = severity_mapping.get(okta_severity, 'medium')
            
            # Extract relevant fields
            actor = alert.get('actor', {})
            client = alert.get('client', {})
            
            # Parse timestamp to datetime object for template rendering
            timestamp_str = alert.get('published', '')
            timestamp_obj = None
            if timestamp_str:
                try:
                    # Handle ISO format strings like '2026-01-08T13:32:15.840Z'
                    timestamp_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except:
                    timestamp_obj = None
            
            recent_alerts.append({
                'id': str(alert.get('_id', '')),
                'event_id': alert.get('uuid', ''),
                'event_type': alert.get('eventType', 'Unknown'),
                'severity': alert_severity,
                'message': alert.get('displayMessage', 'No message available'),
                'username': actor.get('alternateId', 'Unknown'),
                'ip_address': client.get('ipAddress', 'N/A'),
                'timestamp': timestamp_obj or timestamp_str,
                'status': alert.get('status', 'new'),
                'outcome': alert.get('outcome', {}).get('result', 'UNKNOWN')
            })
        
        stats = {
            'total_alerts': total_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
            'recent_alerts': recent_alerts
        }
        # cache.set(cache_key, stats, CACHE_TIMEOUT)  # Temporarily disabled to ensure fresh data
        return stats
    
    def get_alert_types(self) -> List[str]:
        """
        Get list of unique alert/event types that have high/critical severity.
        
        Returns:
            List of alert types
        """
        cache_key = "alert_types:high_critical"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        pipeline = [
            {'$match': {'severity': {'$in': ['WARN', 'ERROR']}}},
            {'$group': {'_id': '$eventType'}},
            {'$sort': {'_id': 1}}
        ]
        result = list(self.collection.aggregate(pipeline))
        alert_types = [doc['_id'] for doc in result if doc['_id']]
        cache.set(cache_key, alert_types, CACHE_TIMEOUT)
        return alert_types
