"""
Models for the traffic_analysis app.

This module contains both MongoDB models (using mongoengine) for storing Okta event data,
and Django models for configuration and UI settings.
"""
from django.db import models
import mongoengine as me
from datetime import datetime
from typing import List, Dict, Any, Optional


class OktaEvent(me.Document):
    """
    MongoDB model for storing Okta events with optimized indexing.
    
    This model stores raw event data from Okta's system log API.
    """
    event_id = me.StringField(required=True, unique=True)
    actor = me.DictField()
    client = me.DictField()
    device = me.DictField()
    authentication_context = me.DictField()
    security_context = me.DictField()
    target = me.ListField(me.DictField())
    outcome = me.DictField()
    debug_context = me.DictField()
    display_message = me.StringField()
    event_type = me.StringField()
    severity = me.StringField()
    published = me.DateTimeField()
    version = me.StringField()
    ip_address = me.StringField()
    geo_data = me.DictField()
    risk_level = me.StringField()
    threat_detected = me.BooleanField(default=False)
    
    # Meta configuration for optimized performance
    meta = {
        'collection': 'okta_events',
        'indexes': [
            # Compound indexes for common query patterns
            {'fields': ['-published', 'event_type'], 'name': 'published_event_type_idx'},
            {'fields': ['event_type', '-published'], 'name': 'event_type_published_idx'},
            {'fields': ['ip_address', '-published'], 'name': 'ip_published_idx'},
            {'fields': ['risk_level', '-published'], 'name': 'risk_published_idx'},
           
            # IMPORTANT: Do not re-add this index - it causes conflicts
            # {'fields': [('target.id', 1), '-published'], 'name': 'target_published_idx'},
            
            # Single field indexes for common filters
            {'fields': ['event_id'], 'unique': True, 'name': 'event_id_idx'},
            {'fields': ['-published'], 'name': 'published_idx'},
            {'fields': ['event_type'], 'name': 'event_type_idx'},
            {'fields': ['severity'], 'name': 'severity_idx'},
            {'fields': ['threat_detected'], 'name': 'threat_idx'},
            
            # TTL index for automatic data expiration - uncomment and set value as needed
            # {'fields': ['published'], 'expireAfterSeconds': 7776000, 'name': 'published_ttl_idx'}  # 90 days
        ],
        'ordering': ['-published'],  # Default ordering
        'auto_create_index': True,
        'index_background': True,  # Create indexes in background
    }
    
    @classmethod
    def get_events_by_timeframe(cls, start_time: datetime, end_time: datetime, 
                               event_type: Optional[str] = None, 
                               limit: int = 1000, 
                               page: int = 1) -> List["OktaEvent"]:
        """
        Optimized method to retrieve events within a specific timeframe
        with optional event type filtering and pagination.
        
        Args:
            start_time: Beginning of the time range
            end_time: End of the time range
            event_type: Optional event type for filtering
            limit: Maximum number of records to return
            page: Page number for pagination (1-indexed)
            
        Returns:
            List of OktaEvent objects matching the criteria
        """
        try:
            query = {"published__gte": start_time, "published__lte": end_time}
            if event_type:
                query["event_type"] = event_type
            
            # Skip calculation for pagination
            skip = (page - 1) * limit
            
            # Use only needed fields in projection to reduce data transfer
            return cls.objects(__raw__=query).only(
                'event_id', 'event_type', 'published', 'severity', 
                'actor', 'display_message', 'outcome', 'ip_address'
            ).skip(skip).limit(limit)
        except Exception as e:
            # Log the error for diagnostics
            import logging
            logging.error(f"Error in get_events_by_timeframe: {str(e)}")
            # Return empty list on error instead of propagating exception
            return []


class OktaMetrics(me.Document):
    """
    MongoDB model for storing pre-aggregated metrics.
    
    This model stores calculated metrics for faster dashboard rendering
    and trend analysis without repeated aggregation.
    """
    metric_id = me.StringField(required=True, unique=True) 
    time_period = me.StringField(required=True)  # 'hourly', 'daily', 'weekly', 'monthly'
    timestamp = me.DateTimeField(required=True)  # Start of the time period
    end_timestamp = me.DateTimeField(required=True)  # End of the time period
    metric_type = me.StringField(required=True)  # Type of metric (login_attempts, failures, etc.)
    value = me.IntField(default=0)  # Numeric value
    data = me.DictField()  # Additional data like breakdowns
    tags = me.ListField(me.StringField())  # For additional filtering
    
    meta = {
        'collection': 'okta_metrics',
        'indexes': [
            # Compound indexes for common lookups
            {'fields': ['metric_type', 'time_period', '-timestamp'], 'name': 'metric_period_time_idx'},
            {'fields': ['-timestamp', 'metric_type'], 'name': 'time_metric_idx'},
            
            # Single field indexes
            {'fields': ['metric_id'], 'unique': True, 'name': 'metric_id_idx'},
            {'fields': ['metric_type'], 'name': 'metric_type_idx'},
            {'fields': ['time_period'], 'name': 'time_period_idx'},
            {'fields': ['-timestamp'], 'name': 'timestamp_idx'},
            
            # TTL index for automatic cleanup of older metrics
            {'fields': ['timestamp'], 'expireAfterSeconds': 15552000, 'name': 'timestamp_ttl_idx'}  # 180 days
        ],
        'ordering': ['-timestamp'],
        'auto_create_index': True,
        'index_background': True,
    }
    
    @classmethod 
    def get_recent_metrics(cls, metric_type: str, time_period: str, limit: int = 30) -> List["OktaMetrics"]:
        """
        Get recent metrics with optimized query pattern.
        
        Args:
            metric_type: Type of metric to retrieve
            time_period: Time period granularity ('hourly', 'daily', etc.)
            limit: Maximum number of records to return
            
        Returns:
            List of OktaMetrics objects matching the criteria
        """
        return cls.objects(
            metric_type=metric_type,
            time_period=time_period
        ).order_by('-timestamp').limit(limit)


class OktaUserProfile(me.Document):
    """
    MongoDB model for storing user profiles and authentication patterns.
    
    This model enriches user data with login patterns and risk assessments
    for security monitoring.
    """
    user_id = me.StringField(required=True, unique=True)
    username = me.StringField()
    display_name = me.StringField()
    email = me.StringField()
    status = me.StringField()
    created = me.DateTimeField()
    last_login = me.DateTimeField()
    last_password_change = me.DateTimeField()
    mfa_factors = me.ListField()
    groups = me.ListField(me.StringField())
    login_locations = me.ListField(me.DictField())
    device_fingerprints = me.ListField(me.DictField())
    risk_score = me.FloatField(default=0)
    
    meta = {
        'collection': 'okta_user_profiles',
        'indexes': [
            # Primary lookup fields
            {'fields': ['user_id'], 'unique': True, 'name': 'user_id_idx'},
            {'fields': ['email'], 'sparse': True, 'name': 'email_idx'},  # Sparse for missing emails
            {'fields': ['username'], 'sparse': True, 'name': 'username_idx'},  # Sparse index
            
            # Risk assessment fields
            {'fields': ['-risk_score'], 'name': 'risk_score_idx'}, 
            {'fields': ['-last_login'], 'name': 'last_login_idx'},
            
            # Compound indices for common operations
            {'fields': ['status', '-last_login'], 'name': 'status_login_idx'},
        ],
        'auto_create_index': True,
        'index_background': True,
    }
    
    @classmethod
    def find_high_risk_users(cls, min_risk_score: float = 7.0, limit: int = 50) -> List["OktaUserProfile"]:
        """
        Find users with high risk scores using optimized query.
        
        Args:
            min_risk_score: Minimum risk score threshold
            limit: Maximum number of records to return
            
        Returns:
            List of high-risk user profiles
        """
        return cls.objects(risk_score__gte=min_risk_score).order_by('-risk_score').limit(limit)
    
    @classmethod
    def find_inactive_users(cls, last_login_cutoff: datetime, limit: int = 100) -> List["OktaUserProfile"]:
        """
        Find users who haven't logged in recently.
        
        Args:
            last_login_cutoff: Datetime cutoff for inactivity
            limit: Maximum number of records to return
            
        Returns:
            List of inactive user profiles
        """
        return cls.objects(last_login__lte=last_login_cutoff).order_by('last_login').limit(limit)


class ForensicEvent(me.Document):
    """
    MongoDB model for digital forensics data.
    
    This model stores detailed event data for security forensics and
    incident response investigations.
    """
    event_id = me.StringField(required=True, unique=True)  
    source_event_id = me.StringField()  # Reference to original event if applicable
    timestamp = me.DateTimeField(required=True)
    event_type = me.StringField(required=True)  # login, logout, data_access, etc.
    severity = me.StringField()  # critical, high, medium, low
    user_id = me.StringField()
    username = me.StringField()
    ip_address = me.StringField()
    user_agent = me.StringField()
    device_info = me.DictField()
    session_id = me.StringField()
    geo_location = me.DictField()
    resource = me.StringField()  # Resource accessed/modified
    action = me.StringField()  # Action performed on resource
    status = me.StringField()  # success, failure
    attributes = me.DictField()  # Additional event-specific attributes
    context = me.DictField()  # Additional context info
    raw_data = me.StringField()  # Raw event data for reference
    
    meta = {
        'collection': 'forensic_events',
        'indexes': [
            # Primary indices
            {'fields': ['event_id'], 'unique': True, 'name': 'event_id_idx'},
            {'fields': ['-timestamp'], 'name': 'timestamp_idx'},
            
            # User activity indices
            {'fields': ['user_id', '-timestamp'], 'name': 'user_timestamp_idx'},
            {'fields': ['username', '-timestamp'], 'name': 'username_timestamp_idx'},
            
            # Network & security indices
            {'fields': ['ip_address', '-timestamp'], 'name': 'ip_timestamp_idx'},
            {'fields': ['session_id', '-timestamp'], 'name': 'session_timestamp_idx'},
            {'fields': ['severity', '-timestamp'], 'name': 'severity_timestamp_idx'},
            
            # Activity type indices
            {'fields': ['event_type', '-timestamp'], 'name': 'event_type_timestamp_idx'},
            {'fields': ['resource', '-timestamp'], 'name': 'resource_timestamp_idx'},
            {'fields': ['action', 'status', '-timestamp'], 'name': 'action_status_timestamp_idx'},
            
            # TTL index for automatic cleanup of older events
            {'fields': ['timestamp'], 'expireAfterSeconds': 7776000, 'name': 'timestamp_ttl_idx'}  # 90 days
        ],
        'ordering': ['-timestamp'],
        'auto_create_index': True,
        'index_background': True,
    }
    
    @classmethod
    def get_user_timeline(cls, user_id: str, 
                         start_time: datetime, 
                         end_time: datetime, 
                         limit: int = 100) -> List["ForensicEvent"]:
        """
        Get a timeline of user activity with optimized query.
        
        Args:
            user_id: ID of the user to get timeline for
            start_time: Beginning of time range
            end_time: End of time range
            limit: Maximum number of events to return
            
        Returns:
            List of chronological events for the user
        """
        return cls.objects(
            user_id=user_id,
            timestamp__gte=start_time,
            timestamp__lte=end_time
        ).order_by('-timestamp').limit(limit)
    
    @classmethod
    def get_session_events(cls, session_id: str) -> List["ForensicEvent"]:
        """
        Get all events for a specific session with optimized query.
        
        Args:
            session_id: Session identifier to filter by
            
        Returns:
            List of events associated with the session
        """
        return cls.objects(session_id=session_id).order_by('timestamp')


class DashboardConfiguration(models.Model):
    """
    Django model for dashboard configuration.
    
    This model stores user preferences and dashboard widget layouts
    for customizable UI experiences.
    """
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    config_json = models.JSONField()
    
    class Meta:
        """Model metadata options."""
        indexes = [
            models.Index(fields=['name'], name='name_idx'),
            models.Index(fields=['is_active'], name='is_active_idx'),
        ]
    
    def __str__(self) -> str:
        """String representation of the configuration."""
        return self.name