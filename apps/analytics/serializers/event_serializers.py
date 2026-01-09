"""
Serializers for Okta event data.

This module contains serializers for transforming OktaEvent models
and related data into JSON format for the API.
"""
from rest_framework import serializers
from apps.analytics.models import OktaEvent, OktaMetrics, OktaUserProfile


class OktaEventSerializer(serializers.Serializer):
    """
    Serializer for OktaEvent MongoDB documents.
    
    Handles transformation of OktaEvent documents to JSON responses.
    Uses explicit field definition for better control over the API.
    """
    event_id = serializers.CharField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    display_message = serializers.CharField(read_only=True)
    published = serializers.DateTimeField(read_only=True)
    severity = serializers.CharField(read_only=True)
    ip_address = serializers.CharField(read_only=True)
    risk_level = serializers.CharField(read_only=True, required=False)
    threat_detected = serializers.BooleanField(read_only=True, required=False)
    
    # Actor is represented as an embedded object
    actor_id = serializers.SerializerMethodField()
    actor_type = serializers.SerializerMethodField()
    actor_display_name = serializers.SerializerMethodField()
    
    # Outcome is represented as flattened fields
    outcome_result = serializers.SerializerMethodField()
    outcome_reason = serializers.SerializerMethodField()
    
    def get_actor_id(self, obj):
        """Extract actor ID from the actor dictionary."""
        if obj.actor and 'id' in obj.actor:
            return obj.actor.get('id')
        return None
    
    def get_actor_type(self, obj):
        """Extract actor type from the actor dictionary."""
        if obj.actor and 'type' in obj.actor:
            return obj.actor.get('type')
        return None
    
    def get_actor_display_name(self, obj):
        """Extract actor display name from the actor dictionary."""
        if obj.actor and 'displayName' in obj.actor:
            return obj.actor.get('displayName')
        return None
    
    def get_outcome_result(self, obj):
        """Extract result from the outcome dictionary."""
        if obj.outcome and 'result' in obj.outcome:
            return obj.outcome.get('result')
        return None
    
    def get_outcome_reason(self, obj):
        """Extract reason from the outcome dictionary."""
        if obj.outcome and 'reason' in obj.outcome:
            return obj.outcome.get('reason')
        return None


class OktaEventDetailSerializer(OktaEventSerializer):
    """
    Detailed serializer for OktaEvent documents.
    
    Extends the base serializer to include more fields for detailed views.
    """
    # Include full nested dictionaries for detailed view
    actor = serializers.DictField(read_only=True)
    client = serializers.DictField(read_only=True)
    device = serializers.DictField(read_only=True, required=False)
    authentication_context = serializers.DictField(read_only=True, required=False)
    security_context = serializers.DictField(read_only=True, required=False)
    outcome = serializers.DictField(read_only=True)
    target = serializers.ListField(read_only=True)
    debug_context = serializers.DictField(read_only=True, required=False)
    
    # Nested target serialization for better API representation
    targets = serializers.SerializerMethodField()
    
    def get_targets(self, obj):
        """Transform target list into a more usable format."""
        if not obj.target:
            return []
            
        result = []
        for target in obj.target:
            target_data = {
                'id': target.get('id'),
                'type': target.get('type'),
                'display_name': target.get('displayName', ''),
                'alternate_id': target.get('alternateId', '')
            }
            result.append(target_data)
        return result


class OktaMetricsSerializer(serializers.Serializer):
    """
    Serializer for OktaMetrics MongoDB documents.
    
    Transforms aggregated metrics for API responses.
    """
    metric_id = serializers.CharField(read_only=True)
    metric_type = serializers.CharField(read_only=True)
    time_period = serializers.CharField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)
    end_timestamp = serializers.DateTimeField(read_only=True)
    value = serializers.IntegerField(read_only=True)
    data = serializers.DictField(read_only=True)
    tags = serializers.ListField(child=serializers.CharField(), read_only=True)


class OktaUserProfileSerializer(serializers.Serializer):
    """
    Serializer for OktaUserProfile MongoDB documents.
    
    Transforms user profile data for API responses.
    """
    user_id = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True, required=False)
    display_name = serializers.CharField(read_only=True, required=False)
    email = serializers.CharField(read_only=True, required=False)
    status = serializers.CharField(read_only=True)
    created = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True, required=False)
    risk_score = serializers.FloatField(read_only=True)
    groups = serializers.ListField(child=serializers.CharField(), read_only=True)
    
    # Method fields for derived/computed properties
    login_count = serializers.SerializerMethodField()
    days_since_login = serializers.SerializerMethodField()
    location_count = serializers.SerializerMethodField()
    device_count = serializers.SerializerMethodField()
    
    def get_login_count(self, obj):
        """Calculate number of logins from login_locations."""
        return len(obj.login_locations) if obj.login_locations else 0
    
    def get_days_since_login(self, obj):
        """Calculate days since last login."""
        if not obj.last_login:
            return None
        from datetime import datetime
        now = datetime.utcnow()
        delta = now - obj.last_login
        return delta.days
    
    def get_location_count(self, obj):
        """Count unique login locations."""
        if not obj.login_locations:
            return 0
        locations = set()
        for location in obj.login_locations:
            if 'city' in location and 'country' in location:
                locations.add((location.get('city', ''), location.get('country', '')))
        return len(locations)
    
    def get_device_count(self, obj):
        """Count unique devices."""
        return len(obj.device_fingerprints) if obj.device_fingerprints else 0