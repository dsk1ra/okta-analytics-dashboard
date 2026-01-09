from rest_framework import serializers


class ForensicEventSerializer(serializers.Serializer):
    """Serializer for forensic events"""
    event_id = serializers.CharField(required=False)
    event_type = serializers.CharField(required=False)
    published = serializers.CharField(required=False)
    risk_level = serializers.CharField(required=False)
    event_hash = serializers.CharField(required=False)
    client_ip = serializers.CharField(required=False)
    actor = serializers.DictField(required=False)
    outcome = serializers.DictField(required=False)
    location = serializers.DictField(required=False)
    authentication_context = serializers.DictField(required=False)
    security_context = serializers.DictField(required=False)
    session = serializers.DictField(required=False)


class SessionChainSerializer(serializers.Serializer):
    """Serializer for session chains"""
    session_id = serializers.CharField()
    session_start = serializers.CharField()
    session_end = serializers.CharField(required=False, allow_null=True)
    session_duration = serializers.CharField(required=False, allow_null=True)
    ip_address = serializers.CharField()
    location = serializers.DictField()
    auth_method = serializers.DictField()
    events = ForensicEventSerializer(many=True)
    event_count = serializers.IntegerField()
    mfa_used = serializers.BooleanField()
    suspicious_activity = serializers.BooleanField()
    user = serializers.CharField()


class GeoMovementSerializer(serializers.Serializer):
    """Serializer for geographic movement analysis"""
    first_login = ForensicEventSerializer()
    second_login = ForensicEventSerializer()
    distance_km = serializers.FloatField()
    hours_between = serializers.FloatField()
    severity = serializers.CharField()
    description = serializers.CharField()
    first_location = serializers.CharField()
    second_location = serializers.CharField()
    user_id = serializers.CharField()
    user_name = serializers.CharField()


class MfaUsageSerializer(serializers.Serializer):
    """Serializer for MFA usage analysis"""
    total_mfa_events = serializers.IntegerField()
    by_factor_type = serializers.DictField()
    by_user = serializers.DictField()
    success_rate = serializers.IntegerField()
    mfa_bypass_attempts = serializers.IntegerField()
    verify_vs_totp = serializers.DictField()


class ForensicTimelineSerializer(serializers.Serializer):
    """Serializer for forensic timeline"""
    events = ForensicEventSerializer(many=True)
    total_count = serializers.IntegerField()
    high_risk_count = serializers.IntegerField()
    medium_risk_count = serializers.IntegerField()


class ForensicSessionsSerializer(serializers.Serializer):
    """Serializer for forensic sessions"""
    session_chains = SessionChainSerializer(many=True)
    chain_count = serializers.IntegerField()
    suspicious_sessions = serializers.IntegerField()


class GeographicAnalysisSerializer(serializers.Serializer):
    """Serializer for geographic analysis"""
    suspicious_movements = GeoMovementSerializer(many=True)
    movement_count = serializers.IntegerField()
    high_severity_count = serializers.IntegerField()
    medium_severity_count = serializers.IntegerField()


class ZeroTrustMetricsSerializer(serializers.Serializer):
    """Serializer for zero trust metrics"""
    average_login_time = serializers.FloatField(required=False, allow_null=True)
    mfa_usage_percentage = serializers.FloatField(required=False)
    failed_login_percentage = serializers.FloatField(required=False)
    device_compliance_percentage = serializers.FloatField(required=False, allow_null=True)
    risk_score = serializers.FloatField(required=False)
    session_anomaly_count = serializers.IntegerField(required=False)
    suspicious_ip_count = serializers.IntegerField(required=False)
    context_aware_access_count = serializers.IntegerField(required=False, allow_null=True)
    
    # Date ranges for reporting
    start_date = serializers.CharField(required=False)
    end_date = serializers.CharField(required=False)