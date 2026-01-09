from rest_framework import serializers
from apps.analytics.models import OktaMetrics

class OktaMetricsSerializer(serializers.Serializer):
    """Serializer for Okta metrics data"""
    metric_id = serializers.CharField(read_only=True)
    metric_type = serializers.CharField(read_only=True)
    time_period = serializers.CharField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)
    end_timestamp = serializers.DateTimeField(read_only=True)
    value = serializers.IntegerField(read_only=True)
    data = serializers.DictField(read_only=True, allow_null=True)
    tags = serializers.ListField(child=serializers.CharField(), read_only=True, allow_null=True)


class TrendPointSerializer(serializers.Serializer):
    """Serializer for a single point in a trend series"""
    date = serializers.CharField(read_only=True)
    value = serializers.IntegerField(read_only=True)


class MetricTrendSerializer(serializers.Serializer):
    """Serializer for a metric trend series with total and points"""
    total = serializers.IntegerField(read_only=True)
    trend = TrendPointSerializer(many=True, read_only=True)


class OktaMetricsSummarySerializer(serializers.Serializer):
    """Serializer for summary of multiple metrics types"""
    login_attempts = MetricTrendSerializer(read_only=True)
    login_failures = MetricTrendSerializer(read_only=True)
    mfa_usage = MetricTrendSerializer(read_only=True)
    geo_access = MetricTrendSerializer(read_only=True)
    time_period = serializers.DictField(read_only=True)