"""
Error handling views for the traffic_analysis app.

This module provides view functions for handling HTTP error responses.
"""
from django.shortcuts import render


def handler404(request, exception):
    """
    Handle 404 Not Found errors.
    
    Args:
        request: The HTTP request object
        exception: The exception that was raised
        
    Returns:
        Rendered 404 error page
    """
    context = {
        'error_code': 404,
        'error_message': 'The page you requested could not be found.',
        'exception': str(exception) if exception else 'Not Found'
    }
    return render(request, 'traffic_analysis/errors.html', context, status=404)


def handler500(request):
    """
    Handle 500 Server Error responses.
    
    Args:
        request: The HTTP request object
        
    Returns:
        Rendered 500 error page
    """
    context = {
        'error_code': 500,
        'error_message': 'An internal server error occurred. Please try again later.',
        'exception': 'Internal Server Error'
    }
    return render(request, 'traffic_analysis/errors.html', context, status=500)