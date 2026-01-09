from rest_framework import serializers

class StatisticsSerializer(serializers.Serializer):
    """
    Serializer for device and application statistics
    """
    days = serializers.IntegerField(default=30)

class DeviceStatisticsSerializer(serializers.Serializer):
    """
    Serializer for device statistics
    """
    devices = serializers.DictField(child=serializers.IntegerField())

class ApplicationStatisticsSerializer(serializers.Serializer):
    """
    Serializer for application statistics
    """
    applications = serializers.DictField(child=serializers.IntegerField())

class BrowserStatisticsSerializer(serializers.Serializer):
    """
    Serializer for browser statistics
    """
    browsers = serializers.DictField(child=serializers.IntegerField())

class OSStatisticsSerializer(serializers.Serializer):
    """
    Serializer for operating system statistics
    """
    operating_systems = serializers.DictField(child=serializers.IntegerField())

class LocationStatisticsSerializer(serializers.Serializer):
    """
    Serializer for location statistics
    """
    locations = serializers.DictField(child=serializers.IntegerField())

class OutcomeStatisticsSerializer(serializers.Serializer):
    """
    Serializer for login outcome statistics
    """
    outcomes = serializers.DictField()


class EventActivitySerializer(serializers.Serializer):
    """Serializer for event activity time-series data."""
    labels = serializers.ListField(child=serializers.CharField())
    successful = serializers.ListField(child=serializers.IntegerField())
    failed = serializers.ListField(child=serializers.IntegerField())
    security = serializers.ListField(child=serializers.IntegerField())


class EventDistributionSerializer(serializers.Serializer):
    """Serializer for event type distribution."""
    labels = serializers.ListField(child=serializers.CharField())
    counts = serializers.ListField(child=serializers.IntegerField())


class RecentEventsSerializer(serializers.Serializer):
    """Serializer for recent events list."""
    uuid = serializers.CharField()
    eventType = serializers.CharField()
    username = serializers.CharField()
    published = serializers.CharField()
    ipAddress = serializers.CharField()
    outcome = serializers.DictField()
    severity = serializers.CharField()

class AllStatisticsSerializer(serializers.Serializer):
    """
    Serializer for all statistics
    """
    devices = serializers.DictField(child=serializers.IntegerField())
    operating_systems = serializers.DictField(child=serializers.IntegerField())
    browsers = serializers.DictField(child=serializers.IntegerField())
    applications = serializers.DictField(child=serializers.IntegerField())
    locations = serializers.DictField(child=serializers.IntegerField())
    outcomes = serializers.DictField()