from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from rest_framework.documentation import include_docs_urls

# Import okta_login_time view
from apps.monitoring.api_views import okta_login_time
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

# Import API views
from .v1.views.forensics_views import ForensicEventsViewSet
from .v1.views.metrics_views import MetricsViewSet
from .v1.views.users_views import UsersViewSet
from .v1.views.events_views import EventsViewSet

# Import function-based views
from .v1.views.forensics_views import (
    forensic_timeline,
    forensic_sessions,
    geographic_analysis,
    mfa_usage,
    zero_trust_metrics,
)
from .v1.views.simulation_views import generate_simulation


# Create a router for v1 ViewSets
v1_router = DefaultRouter()
v1_router.register(r'forensics', ForensicEventsViewSet, basename='forensics')
v1_router.register(r'metrics', MetricsViewSet, basename='metrics')
v1_router.register(r'users', UsersViewSet, basename='users')
v1_router.register(r'events', EventsViewSet, basename='events')

# Setup API documentation with drf-yasg
schema_view = get_schema_view(
    openapi.Info(
        title="Okta Dashboard API",
        default_version='v1',
        description="API for the Okta Dashboard security monitoring system",
        terms_of_service="",
        contact=openapi.Contact(email="admin@example.com"),
        license=openapi.License(name="Proprietary"),
    ),
    public=False,
    permission_classes=(permissions.IsAuthenticated,),
)


# API URL patterns
urlpatterns = [
    # Average login time endpoint
    path('v1/metrics/okta_login_time/', okta_login_time, name='okta_login_time'),

    # API version 1 routes - register via DefaultRouter
    path('v1/', include((v1_router.urls, 'v1'))),
    
    # API version 1 function-based views
    path('v1/forensic/timeline/', forensic_timeline, name='v1_forensic_timeline'),
    path('v1/forensic/sessions/', forensic_sessions, name='v1_forensic_sessions'),
    path('v1/forensic/geographic/', geographic_analysis, name='v1_geographic_analysis'),
    path('v1/forensic/mfa/', mfa_usage, name='v1_mfa_usage'),
    path('v1/forensic/zero-trust/', zero_trust_metrics, name='v1_zero_trust_metrics'),
    path('v1/simulation/generate/', generate_simulation, name='v1_generate_simulation'),
    
    # Legacy compatibility routes - these redirect to v1 versions
    # Using redirects helps with backwards compatibility
    path('forensic/timeline/', forensic_timeline),
    path('forensic/sessions/', forensic_sessions),
    path('forensic/geographic/', geographic_analysis),
    path('forensic/mfa/', mfa_usage),
    path('forensic/zero-trust/', zero_trust_metrics),
    path('simulation/generate/', generate_simulation),

    # API documentation with drf-yasg (Swagger/OpenAPI)
    re_path(r'^docs(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
    # API schema for client-side consumption
    path('schema/', include('rest_framework.urls')),
]