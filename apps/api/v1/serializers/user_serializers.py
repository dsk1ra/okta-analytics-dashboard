from rest_framework import serializers
from apps.analytics.models import OktaUserProfile

class OktaUserProfileSerializer(serializers.Serializer):
    """Serializer for Okta user profiles with basic information"""
    user_id = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True, allow_null=True) 
    display_name = serializers.CharField(read_only=True, allow_null=True)
    email = serializers.EmailField(read_only=True, allow_null=True)
    status = serializers.CharField(read_only=True, allow_null=True)
    created = serializers.DateTimeField(read_only=True, allow_null=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True) 
    risk_score = serializers.FloatField(read_only=True)


class OktaUserDetailSerializer(serializers.Serializer):
    """Serializer for detailed user profile information"""
    user_id = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True, allow_null=True) 
    display_name = serializers.CharField(read_only=True, allow_null=True)
    email = serializers.EmailField(read_only=True, allow_null=True)
    status = serializers.CharField(read_only=True, allow_null=True)
    created = serializers.DateTimeField(read_only=True, allow_null=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    last_password_change = serializers.DateTimeField(read_only=True, allow_null=True)
    mfa_factors = serializers.ListField(read_only=True, allow_null=True)
    groups = serializers.ListField(child=serializers.CharField(), read_only=True, allow_null=True)
    login_locations = serializers.ListField(read_only=True, allow_null=True)
    device_fingerprints = serializers.ListField(read_only=True, allow_null=True)
    risk_score = serializers.FloatField(read_only=True)


class OktaUserRiskSerializer(serializers.Serializer):
    """Serializer for user risk information"""
    user_id = serializers.CharField(read_only=True)
    username = serializers.CharField(read_only=True, allow_null=True)
    email = serializers.EmailField(read_only=True, allow_null=True)
    status = serializers.CharField(read_only=True, allow_null=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    risk_score = serializers.FloatField(read_only=True)
    login_locations = serializers.ListField(read_only=True, allow_null=True)