"""
Device Trust Service for Zero Trust architecture.
This service implements device fingerprinting, verification and trust scoring.
"""

import logging
import base64
import hashlib
import json
import time
from typing import Dict, Optional, Tuple
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

class DeviceTrustService:
    """
    A service for maintaining and validating device trust in a Zero Trust model.
    
    Key capabilities:
    1. Device fingerprinting
    2. Trust score calculation
    3. Device posture verification
    4. Certificate validation
    """
    
    def __init__(self):
        # Trust levels
        self.TRUST_LEVEL_NONE = 0
        self.TRUST_LEVEL_LOW = 1
        self.TRUST_LEVEL_MEDIUM = 2
        self.TRUST_LEVEL_HIGH = 3
        
        # Default minimum trust level required for access
        self.min_trust_level = getattr(settings, 'MIN_DEVICE_TRUST_LEVEL', self.TRUST_LEVEL_MEDIUM)
        
        # Trust score validity period (24 hours)
        self.trust_score_ttl = getattr(settings, 'DEVICE_TRUST_SCORE_TTL', 86400)
        
        # Cache key prefix
        self.cache_prefix = "device_trust:"
        
    def fingerprint_device(self, request) -> str:
        """
        Generate a device fingerprint from request parameters
        
        Args:
            request: The HTTP request object
            
        Returns:
            A unique device fingerprint string
        """
        # Collect device parameters
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        ip = self._get_client_ip(request)
        language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        platform = self._extract_platform(user_agent)
        
        # Include additional parameters if available
        extra_params = {}
        client_hints = self._extract_client_hints(request)
        if client_hints:
            extra_params.update(client_hints)
        
        # Combine parameters
        fingerprint_data = {
            'user_agent': user_agent,
            'ip': ip,
            'language': language,
            'platform': platform,
            **extra_params
        }
        
        # Generate hash of parameters
        fingerprint_json = json.dumps(fingerprint_data, sort_keys=True).encode()
        device_hash = hashlib.sha256(fingerprint_json).hexdigest()
        
        # Include user ID if authenticated to tie device to user
        if hasattr(request, 'user') and request.user.is_authenticated:
            user_id = str(request.user.id)
            combined = f"{user_id}:{device_hash}".encode()
            return hashlib.sha256(combined).hexdigest()
        
        return device_hash
    
    def get_trust_score(self, device_id: str) -> int:
        """
        Get the trust score for a device
        
        Args:
            device_id: The device identifier
            
        Returns:
            Trust level (0-3)
        """
        # Try to get from cache first
        cache_key = f"{self.cache_prefix}trust:{device_id}"
        cached_score = cache.get(cache_key)
        
        if cached_score is not None:
            return cached_score
        
        # Default to lowest trust level if not found
        return self.TRUST_LEVEL_NONE
    
    def calculate_trust_score(self, request, device_id: str) -> int:
        """
        Calculate and store a trust score for a device
        
        Args:
            request: The HTTP request
            device_id: The device identifier
            
        Returns:
            Trust level (0-3)
        """
        # Base trust score starts at lowest
        trust_score = self.TRUST_LEVEL_NONE
        
        # Registered device check (stored in session or database)
        if self._is_registered_device(request, device_id):
            trust_score += 1  # Bump to at least low trust
        
        # Client certificate check
        if self._has_valid_certificate(request):
            trust_score += 1  # Bump by one level
        
        # Device posture check (endpoint security)
        posture_status = self._check_device_posture(request)
        if posture_status:
            trust_score += 1  # Bump by one level
        
        # Cap at highest level
        trust_score = min(trust_score, self.TRUST_LEVEL_HIGH)
        
        # Store in cache
        cache_key = f"{self.cache_prefix}trust:{device_id}"
        cache.set(cache_key, trust_score, self.trust_score_ttl)
        
        return trust_score
    
    def verify_device(self, request) -> Tuple[bool, Dict]:
        """
        Verify if a device meets the minimum trust requirements
        
        Args:
            request: The HTTP request
            
        Returns:
            Tuple of (is_trusted, details)
        """
        # Get or generate device ID
        device_id = request.session.get('device_id')
        if not device_id:
            device_id = self.fingerprint_device(request)
            request.session['device_id'] = device_id
            request.session.modified = True
        
        # Calculate trust score if needed or get from cache
        trust_score = self.calculate_trust_score(request, device_id)
        
        # Check if meets minimum requirements
        is_trusted = trust_score >= self.min_trust_level
        
        details = {
            'device_id': device_id,
            'trust_level': trust_score,
            'min_required': self.min_trust_level,
            'trusted': is_trusted,
        }
        
        return is_trusted, details
    
    def register_device(self, request, device_id: Optional[str] = None) -> str:
        """
        Register a device as trusted for this user
        
        Args:
            request: The HTTP request
            device_id: Optional device ID, will generate one if not provided
            
        Returns:
            The device ID
        """
        if not device_id:
            device_id = self.fingerprint_device(request)
        
        # Store in session
        request.session['device_id'] = device_id
        request.session['registered_device'] = True
        request.session.modified = True
        
        # If user is authenticated, store in database too
        if hasattr(request, 'user') and request.user.is_authenticated:
            from django.contrib.auth.models import User
            user = request.user
            
            # Store using user profile or related model
            # This is a placeholder - implement based on your model structure
            try:
                # Example implementation
                # user_profile, created = UserProfile.objects.get_or_create(user=user)
                # registered_devices = user_profile.registered_devices or []
                # if device_id not in registered_devices:
                #     registered_devices.append(device_id)
                #     user_profile.registered_devices = registered_devices
                #     user_profile.save()
                pass
            except Exception as e:
                logger.error(f"Failed to store device registration: {str(e)}")
        
        return device_id
    
    def _is_registered_device(self, request, device_id: str) -> bool:
        """Check if this is a registered device"""
        # Check session first
        if request.session.get('registered_device') and request.session.get('device_id') == device_id:
            return True
        
        # Check database if user is authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            # This is a placeholder - implement based on your model structure
            try:
                # Example implementation
                # user_profile = UserProfile.objects.get(user=request.user)
                # registered_devices = user_profile.registered_devices or []
                # return device_id in registered_devices
                pass
            except Exception:
                pass
        
        return False
    
    def _has_valid_certificate(self, request) -> bool:
        """Check if the client has a valid certificate"""
        # Client certificate will be in request.META['SSL_CLIENT_CERT'] if using SSL
        client_cert = request.META.get('SSL_CLIENT_CERT')
        if not client_cert:
            return False
            
        # In a real implementation, you would validate the certificate
        # against your CA and check revocation status
        try:
            # This is a placeholder - implement proper certificate validation
            return True
        except Exception as e:
            logger.error(f"Certificate validation error: {str(e)}")
            return False
    
    def _check_device_posture(self, request) -> bool:
        """Check device posture/health from headers or endpoint management system"""
        # Look for custom posture headers that might be set by device management
        posture_header = request.META.get('HTTP_X_DEVICE_POSTURE') 
        if posture_header:
            try:
                posture_data = json.loads(posture_header)
                if posture_data.get('status') == 'healthy':
                    return True
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Invalid device posture header: {str(e)}")
        
        # This could be expanded to check with MDM/EDR systems
        return False
    
    def _extract_client_hints(self, request) -> Dict:
        """Extract client hints from request headers"""
        hints = {}
        
        # User agent client hints
        for header in ['HTTP_SEC_CH_UA', 'HTTP_SEC_CH_UA_MOBILE', 
                       'HTTP_SEC_CH_UA_PLATFORM', 'HTTP_SEC_CH_UA_PLATFORM_VERSION']:
            if header in request.META:
                key = header.lower().replace('http_sec_ch_', '')
                hints[key] = request.META[header]
        
        return hints
    
    def _extract_platform(self, user_agent: str) -> str:
        """Extract platform from user agent string"""
        platforms = {
            'Windows': 'windows',
            'Macintosh': 'mac',
            'iPhone': 'ios',
            'iPad': 'ios',
            'Android': 'android',
            'Linux': 'linux'
        }
        
        for platform, value in platforms.items():
            if platform in user_agent:
                return value
                
        return 'unknown'
    
    def _get_client_ip(self, request) -> str:
        """Get the client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip