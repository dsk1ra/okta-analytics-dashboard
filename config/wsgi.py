"""
WSGI entrypoint for the Django application (production deployments).

Exposes the WSGI callable as ``application`` for compatible servers.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()
