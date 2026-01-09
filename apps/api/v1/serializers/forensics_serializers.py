from rest_framework import serializers
from apps.analytics.models import ForensicEvent

class ForensicEventSerializer(serializers.Serializer):
    """Serializer for forensic events with basic information"""
    event_id = serializers.CharField(read_only=True)
    source_event_id = serializers.CharField(read_only=True, allow_null=True)
    timestamp = serializers.DateTimeField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True, allow_null=True)
    user_id = serializers.CharField(read_only=True, allow_null=True)
    username = serializers.CharField(read_only=True, allow_null=True)
    ip_address = serializers.CharField(read_only=True, allow_null=True)
    resource = serializers.CharField(read_only=True, allow_null=True)
    action = serializers.CharField(read_only=True, allow_null=True)
    status = serializers.CharField(read_only=True, allow_null=True)


class ForensicEventDetailSerializer(serializers.Serializer):
    """Serializer for detailed forensic event information"""
    event_id = serializers.CharField(read_only=True)
    source_event_id = serializers.CharField(read_only=True, allow_null=True)
    timestamp = serializers.DateTimeField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True, allow_null=True)
    user_id = serializers.CharField(read_only=True, allow_null=True)
    username = serializers.CharField(read_only=True, allow_null=True)
    ip_address = serializers.CharField(read_only=True, allow_null=True)
    user_agent = serializers.CharField(read_only=True, allow_null=True)
    device_info = serializers.DictField(read_only=True, allow_null=True)
    session_id = serializers.CharField(read_only=True, allow_null=True)
    geo_location = serializers.DictField(read_only=True, allow_null=True)
    resource = serializers.CharField(read_only=True, allow_null=True)
    action = serializers.CharField(read_only=True, allow_null=True)
    status = serializers.CharField(read_only=True, allow_null=True)
    attributes = serializers.DictField(read_only=True, allow_null=True)
    context = serializers.DictField(read_only=True, allow_null=True)
    raw_data = serializers.CharField(read_only=True, allow_null=True)


class TimelineSerializer(serializers.Serializer):
    """Serializer for event timeline data"""
    events = ForensicEventSerializer(many=True, read_only=True)
    user_id = serializers.CharField(read_only=True, allow_null=True)
    time_range = serializers.DictField(read_only=True)


class SessionAnalysisSerializer(serializers.Serializer):
    """Serializer for session analysis data"""
    session_id = serializers.CharField(read_only=True)
    user_id = serializers.CharField(read_only=True, allow_null=True)
    username = serializers.CharField(read_only=True, allow_null=True)
    start_time = serializers.DateTimeField(read_only=True)
    end_time = serializers.DateTimeField(read_only=True, allow_null=True)
    duration_minutes = serializers.IntegerField(read_only=True)
    ip_address = serializers.CharField(read_only=True, allow_null=True)
    user_agent = serializers.CharField(read_only=True, allow_null=True)
    location = serializers.DictField(read_only=True, allow_null=True)
    events = ForensicEventSerializer(many=True, read_only=True)
    risk_indicators = serializers.DictField(read_only=True, allow_null=True)