from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from apps.analytics.views.event_views import EventListView
from apps.analytics.views.home_views import HomePageView
from apps.okta_integration.views import oauth_callback, login_view, logout_view
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(
        title="OKTA Dashboard API",
        default_version='v1',
        description="API documentation for OKTA Dashboard",
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="contact@mongo.db"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

# Health check view for monitoring services
def health_check(request):
    return JsonResponse({"status": "ok", "service": "okta-dashboard-backend"})

urlpatterns = [
    path('admin/', admin.site.urls),

    # Authentication URLs
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('okta/login/', include('apps.okta_integration.urls')),
    path('okta/callback/', oauth_callback, name='okta_callback'),

    # API endpoints
    path('api/', include('apps.api.urls')),

    # Analytics app (formerly traffic_analysis)
    path('', include('apps.analytics.urls')),

    # Monitoring app (formerly login_tracking)
    path('', include('apps.monitoring.urls')),

    # Monitoring and health check endpoints
    path('health/', health_check, name='health-check'),
    path('metrics/', include('django_prometheus.urls')),

    # API documentation
    path('docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

# Error handlers
handler404 = 'apps.analytics.views.error_views.handler404'
handler500 = 'apps.analytics.views.error_views.handler500'
