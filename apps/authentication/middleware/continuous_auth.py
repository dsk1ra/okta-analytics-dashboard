"""
Continuous Authentication Middleware for ongoing user validation.

This middleware implements the zero trust principle of "never trust, always verify"
by continuously validating the user's authentication status.
"""

import logging
import time
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import logout
from django.shortcuts import redirect

logger = logging.getLogger(__name__)

class ContinuousAuthMiddleware(MiddlewareMixin):
    """
    Middleware that continuously revalidates user authentication.
    
    Implements:
    1. Token revalidation at specified intervals
    2. Context-aware risk assessment
    3. Adaptive authentication based on risk factors
    """
    
    # Set async_mode attribute required for Django 5.2 compatibility
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Exempt paths from continuous authentication
        self.exempt_paths = [
            '/login/',
            '/logout/',
            '/okta/callback/',
            '/health/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
        
        # Revalidation settings
        self.revalidation_interval = getattr(settings, 'TOKEN_REVALIDATION_INTERVAL', 300)  # 5 minutes
        self.min_trust_level = getattr(settings, 'MIN_DEVICE_TRUST_LEVEL', 1)
        self.risk_threshold_ip_change = getattr(settings, 'RISK_THRESHOLD_IP_CHANGE', 'medium')
        
    def process_request(self, request):
        """Process incoming request for continuous authentication"""
        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return None
            
        # Skip if user is not authenticated
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return None
            
        # Get last validation time
        last_validation = request.session.get('auth_last_validated', 0)
        current_time = int(time.time())
        
        # Check if revalidation is needed
        if current_time - last_validation > self.revalidation_interval:
            # Perform token validation
            is_valid = self._validate_token(request)
            if not is_valid:
                logger.warning(f"Token validation failed for user {request.user.username}")
                return self._terminate_session(request)
                
            # Update validation timestamp
            request.session['auth_last_validated'] = current_time
            
        # Assess risk factors
        risk_level = self._assess_risk_factors(request)
        
        # Take action based on risk level
        if risk_level == 'high':
            logger.warning(f"High risk detected for user {request.user.username}")
            return self._terminate_session(request)
        elif risk_level == 'medium':
            # For medium risk, you might want to step-up authentication
            # but for now we'll just log it
            logger.info(f"Medium risk detected for user {request.user.username}")
            
        return None
        
    def _validate_token(self, request):
        """Validate the user's token"""
        # Here you would implement logic to validate the access token
        # This might involve checking with Okta or another service
        
        # For demonstration, we're just returning True
        # In a real implementation, you would:
        # 1. Check token expiration
        # 2. Potentially validate with the identity provider
        # 3. Check for token revocation
        return True
        
    def _assess_risk_factors(self, request):
        """Assess risk factors for the current request"""
        # Here you would implement logic to assess various risk factors
        # such as IP address changes, unusual activity, etc.
        
        # Check for IP address change
        original_ip = request.session.get('client_ip')
        current_ip = self._get_client_ip(request)
        
        if original_ip and original_ip != current_ip:
            # IP address has changed, might be suspicious
            return self.risk_threshold_ip_change
            
        # Check device trust level
        device_trust = request.session.get('device_trust_level', 0)
        if device_trust < self.min_trust_level:
            # Device trust level is too low
            return 'high'
            
        # Default to low risk
        return 'low'
        
    def _terminate_session(self, request):
        """Terminate the user's session"""
        logout(request)
        return redirect(settings.LOGIN_URL + '?reason=security_validation')
        
    def _get_client_ip(self, request):
        """Get the client's IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip