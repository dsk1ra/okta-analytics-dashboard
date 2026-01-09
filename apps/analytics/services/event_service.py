"""
Services for processing and analyzing Okta events.

This module contains business logic for event analysis, metric calculation,
and other operations separate from HTTP request handling.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Callable

from django.conf import settings
from django.core.cache import cache

from apps.analytics.models import OktaEvent, OktaMetrics, ForensicEvent

CACHE_TIMEOUT = getattr(settings, "ANALYTICS_CACHE_TIMEOUT", 300)


def _cached_value(prefix: str, parts: List[str], builder: Callable[[], Any]) -> Any:
    key = f"{prefix}:{':'.join(parts)}"
    cached = cache.get(key)
    if cached is not None:
        return cached
    value = builder()
    cache.set(key, value, CACHE_TIMEOUT)
    return value


class EventService:
    """
    Service for basic event operations.
    
    This class handles common event-related operations like retrieving
    event types, handling basic filtering, etc.
    """
    
    @staticmethod
    def get_event_types() -> List[str]:
        """
        Get a list of all unique event types in the system.
        
        Returns:
            List of event type strings
        """
        return _cached_value(
            "event_types",
            [],
            lambda: OktaEvent.objects().distinct('event_type')
        )
    
    @staticmethod
    def get_severity_counts(start_time: datetime, end_time: datetime) -> Dict[str, int]:
        """
        Get counts of events by severity level within a time period.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            
        Returns:
            Dictionary with severity levels and counts
        """
        pipeline = [
            {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"_id": 1}}
        ]
        cache_parts = [start_time.isoformat(), end_time.isoformat()]
        return _cached_value(
            "severity_counts",
            cache_parts,
            lambda: {
                item['_id']: item['count']
                for item in OktaEvent.objects.aggregate(*pipeline)
                if item['_id']
            }
        )


class EventAnalysisService:
    """
    Service for analyzing and processing Okta event data.
    
    This class handles business logic for event analysis, metric calculation,
    and risk assessment without mixing with HTTP concerns.
    """
    
    @staticmethod
    def get_event_metrics(
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Calculate metrics from event data within a time period.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            event_types: Optional list of event types to include
            
        Returns:
            Dictionary containing calculated metrics
        """
        cache_parts = [
            start_time.isoformat(),
            end_time.isoformat(),
            ",".join(sorted(event_types)) if event_types else "all",
        ]

        def build_metrics() -> Dict[str, Any]:
            query = {"published__gte": start_time, "published__lte": end_time}
            if event_types:
                query["event_type__in"] = event_types

            events = OktaEvent.objects(__raw__=query)

            metrics: Dict[str, Any] = {
                "total_events": events.count(),
                "event_types": {},
                "severities": {},
                "outcomes": {},
                "hourly_distribution": [0] * 24
            }

            for event in events:
                event_type = event.event_type
                if event_type not in metrics["event_types"]:
                    metrics["event_types"][event_type] = 0
                metrics["event_types"][event_type] += 1

                severity = event.severity
                if severity not in metrics["severities"]:
                    metrics["severities"][severity] = 0
                metrics["severities"][severity] += 1

                if event.outcome and "result" in event.outcome:
                    outcome = event.outcome["result"]
                    if outcome not in metrics["outcomes"]:
                        metrics["outcomes"][outcome] = 0
                    metrics["outcomes"][outcome] += 1

                hour = event.published.hour
                metrics["hourly_distribution"][hour] += 1

            return metrics

        return _cached_value("event_metrics", cache_parts, build_metrics)
    
    @staticmethod
    def get_top_ip_addresses(
        start_time: datetime,
        end_time: datetime,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get the top IP addresses by event count.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            limit: Maximum number of IP addresses to return
            
        Returns:
            List of dictionaries with ip and count fields
        """
        pipeline = [
            {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
            {"$match": {"ip_address": {"$ne": None}}},
            {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit},
            {"$project": {"_id": 0, "ip": "$_id", "count": 1}}
        ]

        cache_parts = [start_time.isoformat(), end_time.isoformat(), str(limit)]
        return _cached_value(
            "top_ips",
            cache_parts,
            lambda: list(OktaEvent.objects.aggregate(*pipeline))
        )
    
    @staticmethod
    def get_user_activity(
        user_id: str,
        start_time: datetime, 
        end_time: datetime,
        limit: int = 100
    ) -> Tuple[List[OktaEvent], Dict[str, Any]]:
        """
        Get a timeline of user activity and summary metrics.
        
        Args:
            user_id: ID of the user to analyze
            start_time: Beginning of time period
            end_time: End of time period
            limit: Maximum number of events to return
            
        Returns:
            Tuple of (event list, activity metrics)
        """
        # Query for user events
        query = {
            "published__gte": start_time,
            "published__lte": end_time,
            # Match events where user ID appears in actor or targets
            "$or": [
                {"actor.id": user_id},
                {"target.id": user_id}
            ]
        }
        
        # Get events
        events = list(OktaEvent.objects(__raw__=query).order_by("-published").limit(limit))
        
        # Calculate metrics
        metrics = {
            "total_events": len(events),
            "login_count": 0,
            "failed_login_count": 0,
            "ip_addresses": set(),
            "devices": set(),
            "applications_accessed": set()
        }
        
        # Process events for metrics
        for event in events:
            # Count logins
            if event.event_type == "user.session.start":
                metrics["login_count"] += 1
            
            # Count failed logins
            if event.event_type == "user.authentication.auth_via_mfa" and \
               event.outcome and event.outcome.get("result") == "FAILURE":
                metrics["failed_login_count"] += 1
            
            # Track IP addresses
            if event.ip_address:
                metrics["ip_addresses"].add(event.ip_address)
            
            # Track devices
            if event.client and "device" in event.client:
                device = event.client["device"]
                if isinstance(device, str):
                    metrics["devices"].add(device)
                elif isinstance(device, dict) and "name" in device:
                    metrics["devices"].add(device["name"])
            
            # Track applications accessed
            if event.target:
                for target in event.target:
                    if target.get("type") == "AppInstance" and "displayName" in target:
                        metrics["applications_accessed"].add(target["displayName"])
        
        # Convert sets to lists for serialization
        metrics["ip_addresses"] = list(metrics["ip_addresses"])
        metrics["devices"] = list(metrics["devices"])
        metrics["applications_accessed"] = list(metrics["applications_accessed"])
        
        return events, metrics
    
    @staticmethod
    def detect_anomalous_events(
        start_time: datetime,
        end_time: datetime,
        limit: int = 20
    ) -> List[OktaEvent]:
        """
        Detect potentially anomalous events based on risk scoring.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            limit: Maximum number of events to return
            
        Returns:
            List of potentially anomalous events
        """
        # Base query for time range
        query = {"published__gte": start_time, "published__lte": end_time}
        
        # Look for known indicators of suspicious activity
        anomaly_indicators = {
            "$or": [
                # High risk level events
                {"risk_level": "HIGH"},
                # Threat detected
                {"threat_detected": True},
                # Failed authentications
                {
                    "event_type": {"$in": ["user.authentication.auth_via_mfa", "user.authentication.sso"]},
                    "outcome.result": "FAILURE"
                },
                # Multiple locations/IPs for same user
                {"ip_address": {"$ne": None}},
                # Admin privilege operations
                {"event_type": {"$regex": "^system\\."}},
                # Password and MFA changes
                {"event_type": {"$in": ["user.account.reset_password", "user.mfa.factor.update"]}}
            ]
        }
        
        # Combine with base query
        query.update(anomaly_indicators)
        
        # Get potentially anomalous events
        events = list(OktaEvent.objects(__raw__query=query).order_by("-published").limit(limit))
        
        return events


class LogAnalysisService:
    """
    Service for analyzing and processing log data for dashboard display.
    
    This class handles business logic for log analysis, statistics calculation,
    and visualization data preparation.
    """
    
    @staticmethod
    def get_log_dashboard_metrics(
        start_time: datetime,
        end_time: datetime,
        limit: int = 1000
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive metrics from log data for dashboard display.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            limit: Maximum number of logs to analyze (for performance)
            
        Returns:
            Dictionary containing calculated metrics for dashboard
        """
        cache_parts = [start_time.isoformat(), end_time.isoformat(), str(limit)]

        def build_metrics() -> Dict[str, Any]:
            query = {"published__gte": start_time, "published__lte": end_time}
            logs = OktaEvent.objects(__raw__=query).limit(limit)

            dashboard_metrics = {
                "summary": {
                    "total_logs": logs.count(),
                    "time_period": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                        "days": (end_time - start_time).days
                    }
                },
                "severity_distribution": {},
                "hourly_distribution": [0] * 24,
                "daily_trend": {},
                "top_sources": [],
                "top_log_types": []
            }

            severity_pipeline = [
                {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}}
            ]
            severity_results = OktaEvent.objects.aggregate(*severity_pipeline)
            dashboard_metrics["severity_distribution"] = {
                item['_id'] if item['_id'] else 'unknown': item['count']
                for item in severity_results
            }

            for log in logs:
                hour = log.published.hour
                dashboard_metrics["hourly_distribution"][hour] += 1

            daily_pipeline = [
                {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
                {"$group": {
                    "_id": {
                        "$dateToString": {"format": "%Y-%m-%d", "date": "$published"}
                    },
                    "count": {"$sum": 1}
                }},
                {"$sort": {"_id": 1}}
            ]
            daily_results = OktaEvent.objects.aggregate(*daily_pipeline)

            for result in daily_results:
                date_str = result['_id']
                count = result['count']
                dashboard_metrics["daily_trend"][date_str] = count

            source_pipeline = [
                {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
                {"$match": {"ip_address": {"$ne": None}}},
                {"$group": {"_id": "$ip_address", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            source_results = OktaEvent.objects.aggregate(*source_pipeline)
            dashboard_metrics["top_sources"] = [
                {"source": item['_id'], "count": item['count']}
                for item in source_results
            ]

            type_pipeline = [
                {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
                {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            type_results = OktaEvent.objects.aggregate(*type_pipeline)
            dashboard_metrics["top_log_types"] = [
                {"type": item['_id'], "count": item['count']}
                for item in type_results
            ]

            return dashboard_metrics

        return _cached_value("log_dashboard_metrics", cache_parts, build_metrics)
    
    @staticmethod
    def get_log_statistics_comparison(
        start_time: datetime,
        end_time: datetime,
        previous_start_time: datetime,
        previous_end_time: datetime
    ) -> Dict[str, Any]:
        """
        Compare log statistics between current and previous time periods.
        
        Args:
            start_time: Beginning of current period
            end_time: End of current period
            previous_start_time: Beginning of previous period
            previous_end_time: End of previous period
            
        Returns:
            Dictionary with comparison metrics
        """
        cache_parts = [
            start_time.isoformat(),
            end_time.isoformat(),
            previous_start_time.isoformat(),
            previous_end_time.isoformat(),
        ]

        def build_comparison() -> Dict[str, Any]:
            current_count = OktaEvent.objects(
                published__gte=start_time,
                published__lte=end_time
            ).count()

            previous_count = OktaEvent.objects(
                published__gte=previous_start_time,
                published__lte=previous_end_time
            ).count()

            percent_change = 0
            if previous_count > 0:
                percent_change = ((current_count - previous_count) / previous_count) * 100

            current_severity = LogAnalysisService._get_severity_distribution(start_time, end_time)
            previous_severity = LogAnalysisService._get_severity_distribution(previous_start_time, previous_end_time)

            return {
                "current_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "count": current_count,
                    "severity_distribution": current_severity
                },
                "previous_period": {
                    "start": previous_start_time.isoformat(),
                    "end": previous_end_time.isoformat(),
                    "count": previous_count,
                    "severity_distribution": previous_severity
                },
                "changes": {
                    "count_change": current_count - previous_count,
                    "percent_change": round(percent_change, 2),
                    "is_increasing": current_count > previous_count
                }
            }

        return _cached_value("log_stats_compare", cache_parts, build_comparison)
    
    @staticmethod
    def _get_severity_distribution(start_time: datetime, end_time: datetime) -> Dict[str, int]:
        """
        Helper method to get severity distribution for a time period.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            
        Returns:
            Dictionary with severity levels and counts
        """
        pipeline = [
            {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]

        cache_parts = [start_time.isoformat(), end_time.isoformat()]
        return _cached_value(
            "severity_distribution",
            cache_parts,
            lambda: {
                item['_id'] if item['_id'] else 'unknown': item['count']
                for item in OktaEvent.objects.aggregate(*pipeline)
            }
        )
    
    @staticmethod
    def get_log_volume_by_timeframe(
        start_time: datetime,
        end_time: datetime,
        interval: str = 'day'
    ) -> List[Dict[str, Any]]:
        """
        Get log volume metrics grouped by time intervals.
        
        Args:
            start_time: Beginning of time period
            end_time: End of time period
            interval: Grouping interval ('hour', 'day', 'week', 'month')
            
        Returns:
            List of dictionaries with timestamp and count
        """
        # Format string based on interval
        format_string = '%Y-%m-%d'
        if interval == 'hour':
            format_string = '%Y-%m-%d %H:00'
        elif interval == 'week':
            format_string = '%Y-%U'  # Year and week number
        elif interval == 'month':
            format_string = '%Y-%m'
        
        # Aggregation pipeline
        pipeline = [
            {"$match": {"published": {"$gte": start_time, "$lte": end_time}}},
            {"$group": {
                "_id": {
                    "$dateToString": {"format": format_string, "date": "$published"}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]

        cache_parts = [start_time.isoformat(), end_time.isoformat(), interval]
        return _cached_value(
            "log_volume_timeframe",
            cache_parts,
            lambda: [
                {"timestamp": item['_id'], "count": item['count']}
                for item in OktaEvent.objects.aggregate(*pipeline)
            ]
        )