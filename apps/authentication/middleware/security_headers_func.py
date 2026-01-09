import random, string, time
from asgiref.sync import iscoroutinefunction
from django.template.response import SimpleTemplateResponse
from django.utils.decorators import sync_and_async_middleware
from django.conf import settings

@sync_and_async_middleware
def security_headers_middleware(get_response):
    """
    Middleware that adds security headers and CSP nonce to requests and responses.
    This function-based middleware supports both sync and async contexts.
    """
    is_async = iscoroutinefunction(get_response)
    
    # Synchronous version
    if not is_async:
        def middleware(request):
            # Generate nonce for this request
            request.nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            request._start_time = time.time()
            
            # Get response from view
            response = get_response(request)
            
            # Add security headers to all non-template responses
            if not isinstance(response, SimpleTemplateResponse):
                response = add_security_headers(request, response)
            
            # Add timing header
            if hasattr(request, "_start_time"):
                duration = (time.time() - request._start_time) * 1000
                response["Server-Timing"] = f"app;dur={duration:.0f}"
            
            return response
    else:
        # Asynchronous version
        async def middleware(request):
            # Generate nonce for this request
            request.nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            request._start_time = time.time()
            
            # Get response from view
            response = await get_response(request)
            
            # Add security headers to all non-template responses
            if not isinstance(response, SimpleTemplateResponse):
                response = add_security_headers(request, response)
            
            # Add timing header
            if hasattr(request, "_start_time"):
                duration = (time.time() - request._start_time) * 1000
                response["Server-Timing"] = f"app;dur={duration:.0f}"
            
            return response
            
    return middleware

def process_template_response(request, response):
    """
    Process template responses to add the nonce and security headers.
    """
    # Get the nonce from the request
    nonce = getattr(request, 'nonce', None)
    if not nonce:
        nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        request.nonce = nonce
    
    # Make sure the template context has the nonce
    if hasattr(response, 'context_data') and response.context_data is not None:
        response.context_data['nonce'] = nonce
    
    # Add security headers to the response
    response = add_security_headers(request, response)
    
    return response

def add_security_headers(request, response):
    """Add all security headers to the response."""
    # Get the nonce from the request
    nonce = getattr(request, 'nonce', None)
    if not nonce:
        nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    # Define Content Security Policy
    csp = [
        # Default deny everything except what is explicitly allowed
        "default-src 'none'",
        
        # Allow scripts from self and with our nonce
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com",
        f"script-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com",
        
        # Allow styles
        f"style-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com",
        f"style-src-elem 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com",
        
        # Allow images and fonts with restrictive sources
        "img-src 'self' data: https://cdn.jsdelivr.net https://images.unsplash.com https://randomuser.me",
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        
        # Restrict connections, frames and other elements
        "connect-src 'self'",
        "frame-src 'none'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "upgrade-insecure-requests",
        
        # Add new security directives
        "manifest-src 'self'",
        "media-src 'self'",
        "worker-src 'self'",
        # Removing prefetch-src as it's not a recognized directive
        
        # Block access to document.cookie from JavaScript
        "require-trusted-types-for 'script'",
        
        # Report CSP violations if a reporting URL is configured
        getattr(settings, 'CSP_REPORT_URI', False) and f"report-uri {settings.CSP_REPORT_URI}" or "",
        getattr(settings, 'CSP_REPORT_TO', False) and f"report-to {settings.CSP_REPORT_TO}" or "",
    ]
    
    # Filter out empty directives
    csp = [directive for directive in csp if directive]
    
    response["Content-Security-Policy"] = "; ".join(csp)
    
    # Permissions policy - restrictive by default
    response["Permissions-Policy"] = (
        "accelerometer=(), "
        "camera=(), "
        "geolocation=(), "
        "gyroscope=(), "
        "magnetometer=(), "
        "microphone=(), "
        "payment=(), "
        "usb=(), "
        "interest-cohort=()"  # Block FLoC tracking
    )
    
    # Cross-Origin headers
    response["Cross-Origin-Embedder-Policy"] = "require-corp"
    response["Cross-Origin-Opener-Policy"] = "same-origin"
    response["Cross-Origin-Resource-Policy"] = "same-origin"
    
    # Add HSTS header - enforce HTTPS
    if not settings.DEBUG:
        response["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        
    # Clear-Site-Data header for logout pages - logout is typically /logout/
    if request.path == '/logout/':
        response["Clear-Site-Data"] = '"cache", "cookies", "storage", "executionContexts"'
        
    # Removed Feature-Policy (deprecated) - we're now using Permissions-Policy only
    
    # Add a request ID for traffic tracing in a Zero Trust network
    if not response.has_header('X-Request-ID') and hasattr(request, 'id'):
        response['X-Request-ID'] = getattr(request, 'id', '')
        
    # Add cache control headers to prevent sensitive data caching
    if request.path.startswith('/api/') or request.path.startswith('/dashboard/'):
        response["Cache-Control"] = "no-store, max-age=0"
        response["Pragma"] = "no-cache"
        
    return response
