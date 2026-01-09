from rest_framework import serializers
from apps.analytics.models import OktaEvent

class OktaEventListSerializer(serializers.Serializer):
    """Serializer for listing Okta events with minimal fields"""
    event_id = serializers.CharField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    display_message = serializers.CharField(read_only=True)
    published = serializers.DateTimeField(read_only=True)
    ip_address = serializers.CharField(read_only=True, allow_null=True)
    actor = serializers.DictField(read_only=True, allow_null=True)
    outcome = serializers.DictField(read_only=True, allow_null=True)
    risk_level = serializers.CharField(read_only=True, allow_null=True)
    threat_detected = serializers.BooleanField(read_only=True)


class OktaEventDetailSerializer(serializers.Serializer):
    """Serializer for detailed view of an Okta event"""
    event_id = serializers.CharField(read_only=True)
    event_type = serializers.CharField(read_only=True)
    severity = serializers.CharField(read_only=True)
    display_message = serializers.CharField(read_only=True)
    published = serializers.DateTimeField(read_only=True)
    ip_address = serializers.CharField(read_only=True, allow_null=True)
    actor = serializers.DictField(read_only=True, allow_null=True)
    client = serializers.DictField(read_only=True, allow_null=True)
    device = serializers.DictField(read_only=True, allow_null=True)
    authentication_context = serializers.DictField(read_only=True, allow_null=True)
    security_context = serializers.DictField(read_only=True, allow_null=True)
    target = serializers.ListField(read_only=True, allow_null=True)
    outcome = serializers.DictField(read_only=True, allow_null=True)
    debug_context = serializers.DictField(read_only=True, allow_null=True)
    version = serializers.CharField(read_only=True, allow_null=True)
    geo_data = serializers.DictField(read_only=True, allow_null=True)
    risk_level = serializers.CharField(read_only=True, allow_null=True)
    threat_detected = serializers.BooleanField(read_only=True)


class EventStatisticsSerializer(serializers.Serializer):
    """Serializer for event statistics data"""
    event_types = serializers.DictField(read_only=True)
    severities = serializers.DictField(read_only=True)
    time_period = serializers.DictField(read_only=True)