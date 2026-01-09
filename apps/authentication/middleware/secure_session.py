"""
Secure Session Management Middleware for Zero Trust model.
This middleware implements secure session handling with context validation.
"""

import logging
import time
import secrets
from datetime import datetime
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from django.shortcuts import redirect

logger = logging.getLogger(__name__)

class SecureSessionMiddleware(MiddlewareMixin):
    """
    Zero Trust Session Management Middleware.
    
    Implements:
    1. Session context binding
    2. Session rotation
    3. Inactivity detection and termination
    4. Concurrency control
    """
    
    # Django 5.2+ requires this attribute for middleware
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Paths exempt from session security checks
        self.exempt_paths = [
            '/login/',
            '/logout/',
            '/okta/callback/',
            '/health/',
            '/api/public/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
        
        # Session settings
        self.max_session_idle = getattr(settings, 'SECURE_SESSION_IDLE_TIMEOUT', 1800)  # 30 minutes
        self.session_absolute_timeout = getattr(settings, 'SECURE_SESSION_ABSOLUTE_TIMEOUT', 28800)  # 8 hours
        self.rotate_session_after = getattr(settings, 'SECURE_SESSION_ROTATE_AFTER', 3600)  # 1 hour
        self.enforce_single_session = getattr(settings, 'SECURE_SESSION_ENFORCE_SINGLE', True)
        self.session_grace_period = getattr(settings, 'SECURE_SESSION_GRACE_PERIOD', 60)  # 1 minute
        self.cache_prefix = "secure_session:"
        
    def process_request(self, request):
        """Process incoming request for session security"""
        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return None
            
        # Skip if user is not present or not authenticated
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return None
        
        # Get session metadata
        created_time = request.session.get('session_created_time')
        last_activity = request.session.get('last_activity')
        session_id = request.session.session_key
        user_id = request.user.id
        
        # Set session creation time if not already set
        if not created_time:
            request.session['session_created_time'] = int(time.time())
            request.session.modified = True
            return None
            
        current_time = int(time.time())
        
        # Check session absolute timeout
        if current_time - created_time > self.session_absolute_timeout:
            logger.info(f"Session absolute timeout reached for user {request.user.username}")
            return self._terminate_session(request, "Your session has expired due to maximum time limit.")
            
        # Check session idle timeout
        if last_activity and (current_time - last_activity > self.max_session_idle):
            logger.info(f"Session idle timeout reached for user {request.user.username}")
            return self._terminate_session(request, "Your session has expired due to inactivity.")
            
        # Check if session needs rotation
        if last_activity and (current_time - last_activity > self.rotate_session_after):
            logger.debug(f"Rotating session for user {request.user.username}")
            self._rotate_session(request)
            
        # Check for concurrent sessions if enabled
        if self.enforce_single_session:
            if not self._validate_single_session(request, user_id, session_id):
                logger.warning(f"Concurrent session detected for user {request.user.username}")
                return self._terminate_session(request, "Your account has been logged in from another location.")
                
        # Update last activity time
        request.session['last_activity'] = current_time
        request.session.modified = True
        
        return None
        
    def _terminate_session(self, request, message=None):
        """Terminate the current session and redirect to login"""
        from django.contrib.auth import logout
        from django.contrib import messages
        
        # Add message if provided
        if message and hasattr(request, '_messages'):
            messages.warning(request, message)
        
        # Log the user out
        logout(request)
        
        # Redirect to login
        return HttpResponseRedirect(reverse('okta_login'))
        
    def _rotate_session(self, request):
        """Rotate the session for security"""
        if not hasattr(request, 'session'):
            return
            
        # Remember important session data
        important_keys = ['access_token', 'refresh_token', 'id_token', 'last_activity',
                          'session_created_time', 'device_id', 'client_ip', 'user_agent']
        saved_data = {}
        
        for key in important_keys:
            if key in request.session:
                saved_data[key] = request.session[key]
                
        # Create a new session
        request.session.flush()
        request.session.cycle_key()
        
        # Restore important data
        for key, value in saved_data.items():
            request.session[key] = value
            
        # Update rotation time
        request.session['session_last_rotated'] = int(time.time())
        request.session.modified = True
        
        # Generate a new CSRF token
        request.META['CSRF_COOKIE_USED'] = True
        
    def _validate_single_session(self, request, user_id, session_id):
        """Validate that this is the only active session for this user"""
        # Skip for superusers - they may need multiple sessions
        if request.user.is_superuser:
            return True
            
        current_time = int(time.time())
        cache_key = f"{self.cache_prefix}user:{user_id}"
        
        # Get current active session data
        active_session = cache.get(cache_key)
        
        # If no active session is recorded, register this one
        if not active_session:
            session_data = {
                'session_id': session_id,
                'timestamp': current_time,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'remote_addr': self._get_client_ip(request)
            }
            cache.set(cache_key, session_data)
            return True
            
        # If this is the active session, update timestamp
        if active_session.get('session_id') == session_id:
            active_session['timestamp'] = current_time
            cache.set(cache_key, active_session)
            return True
            
        # If another session is active but within grace period, allow this one
        # and update the active session to this one
        last_active = active_session.get('timestamp', 0)
        if current_time - last_active > self.session_grace_period:
            session_data = {
                'session_id': session_id,
                'timestamp': current_time,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'remote_addr': self._get_client_ip(request)
            }
            cache.set(cache_key, session_data)
            return True
            
        # Another session is active and still within grace period
        return False
        
    def _get_client_ip(self, request):
        """Get the client's IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip