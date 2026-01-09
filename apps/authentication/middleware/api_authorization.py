"""
API Authorization Middleware for enforcing API permissions.

This middleware implements least privilege access to API endpoints by validating
permissions against configured scopes.
"""

import logging
import re
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse

logger = logging.getLogger(__name__)

class APIAuthorizationMiddleware(MiddlewareMixin):
    """
    Middleware that enforces API authorization based on token scopes.
    
    Implements:
    1. Path-based permission enforcement
    2. Method-specific permissions
    3. Scope validation for API endpoints
    """
    
    # Set async_mode attribute required for Django 5.2 compatibility
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Get API permissions from settings
        self.api_permissions = getattr(settings, 'API_PERMISSIONS', {})
        self.default_scope = getattr(settings, 'DEFAULT_API_SCOPE', 'okta.dashboard.read')
        
        # Paths exempt from API authorization
        self.exempt_paths = [
            '/admin/',
            '/login/',
            '/logout/',
            '/okta/callback/',
            '/health/',
            '/static/',
            '/media/',
            '/favicon.ico',
            '/docs/',
            '/redoc/',
        ]
    
    def process_request(self, request):
        """Process incoming request for API authorization"""
        # Skip exempt paths
        if any(request.path.startswith(path) for path in self.exempt_paths):
            return None
            
        # Only apply to API paths
        if not request.path.startswith('/api/'):
            return None
            
        # Skip if user is not authenticated
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return None
            
        # Get token scopes from session
        token_scopes = request.session.get('token_scopes', [])
        
        # Default to empty list if not a list
        if not isinstance(token_scopes, list):
            token_scopes = [self.default_scope] if self.default_scope else []
            
        # Superusers bypass scope checks
        if hasattr(request.user, 'is_superuser') and request.user.is_superuser:
            return None
            
        # Check permissions for this path
        required_scopes = self._get_required_scopes(request.path, request.method)
        
        if not required_scopes:
            # No specific permissions required
            return None
        
        # Check if user has any of the required scopes
        has_permission = any(scope in token_scopes for scope in required_scopes)
        
        if not has_permission:
            logger.warning(
                f"Access denied for {request.user.username} to {request.path} "
                f"(method: {request.method}). Required scopes: {required_scopes}, "
                f"User scopes: {token_scopes}"
            )
            return JsonResponse({
                'error': 'insufficient_scope',
                'error_description': 'You do not have permission to access this resource',
                'required_scopes': required_scopes
            }, status=403)
            
        return None
        
    def _get_required_scopes(self, path, method):
        """Get required scopes for the given path and method"""
        for pattern, scopes in self.api_permissions.items():
            # Check if the path matches the pattern
            if re.search(pattern, path):
                # If scopes is a dict, it's method-specific
                if isinstance(scopes, dict):
                    return scopes.get(method, scopes.get('*', []))
                # Otherwise, it's a list of scopes for all methods
                return scopes
                
        # Default to empty list (no specific permissions required)
        return []