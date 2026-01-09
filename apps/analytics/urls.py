"""
URL patterns for the traffic_analysis app.

This module defines URL routes for traffic analysis endpoints.
"""
from django.urls import path

from apps.analytics.views.event_views import (
    EventsPageView,
    EventListView,
    EventDetailView,
    EventMetricsView
)
from apps.analytics.views.log_views import (
    LogDashboardView,
    LogStatisticsAPIView,
    LogComparisonView,
    log_trends
)
from apps.analytics.views.home_views import home_page_view, DashboardHomeView
from apps.analytics.views.user_views import UserDashboardView
from apps.analytics.views.alert_views import (
    AlertDashboardView,
    AlertDetailPageView,
    AlertListView,
    AlertDetailView
)
from apps.analytics.views.metric_views import (
    MetricsDashboardView,
    login_events_stats,
    failed_login_stats,
    security_events_stats,
    total_events_stats,
    auth_metrics_stats
)
from apps.analytics.views.report_views import (
    ReportDashboardView, 
    generate_report, 
    configure_report, 
    get_report_history,
    manage_templates,
    template_detail
)
from apps.analytics.views.setting_views import SettingsDashboardView
from apps.analytics.views.diagnostic_views import mongodb_status
from apps.analytics.views.statistics_views import (
    DeviceStatisticsView,
    BrowserStatisticsView,
    OSStatisticsView,
    ApplicationStatisticsView,
    LocationStatisticsView,
    OutcomeStatisticsView,
    AllStatisticsView,
    EventActivityStatisticsView,
    EventDistributionStatisticsView,
    RecentEventsView,
)

app_name = "traffic_analysis"

urlpatterns = [
    # Public pages
    path('', home_page_view, name='home'),
    
    # Dashboard for authenticated users
    path('dashboard/', DashboardHomeView.as_view(), name='dashboard'),
    
    # HTML UI endpoints
    path('events/', EventsPageView.as_view(), name='events_page'),
    path('events/detail/<str:event_id>/', EventDetailView.as_view(), name='event_detail_page'),
    path('logs/', LogDashboardView.as_view(), name='logs_dashboard'),
    path('users/', UserDashboardView.as_view(), name='users_dashboard'),
    path('alerts/', AlertDashboardView.as_view(), name='alerts_dashboard'),
    path('alerts/detail/', AlertDetailPageView.as_view(), name='alert_detail_page'),
    path('metrics/', MetricsDashboardView.as_view(), name='metrics_dashboard'),
    path('reports/', ReportDashboardView.as_view(), name='reports_dashboard'),
    path('api/reports/generate/', generate_report, name='generate_report'),
    path('api/reports/configure/', configure_report, name='configure_report'),
    path('api/reports/history/', get_report_history, name='get_report_history'),
    path('api/reports/templates/', manage_templates, name='manage_templates'),
    path('api/reports/templates/<str:template_id>/', template_detail, name='template_detail'),
    path('settings/', SettingsDashboardView.as_view(), name='settings_dashboard'),
    
    # API endpoints
    path('api/events/', EventListView.as_view(), name='event_list'),
    path('api/events/<str:event_id>/', EventDetailView.as_view(), name='event_detail'),
    path('api/metrics/', EventMetricsView.as_view(), name='event_metrics'),
    
    # Alert API endpoints
    path('api/alerts/', AlertListView.as_view(), name='alert_list'),
    path('api/alerts/<str:alert_id>/', AlertDetailView.as_view(), name='alert_detail'),
    
    # Log API endpoints
    path('api/logs/statistics/', LogStatisticsAPIView.as_view(), name='log_statistics'),
    path('api/logs/comparison/', LogComparisonView.as_view(), name='log_comparison'),
    path('api/logs/trends/', log_trends, name='log_trends'),
    
    # Login statistics endpoint
    path('api/statistics/login-events/', login_events_stats, name='login_events_stats'),
    path('api/statistics/failed-logins/', failed_login_stats, name='failed_login_stats'),
    path('api/statistics/security-events/', security_events_stats, name='security_events_stats'),
    path('api/statistics/total-events/', total_events_stats, name='total_events_stats'),
    path('api/statistics/auth-metrics/', auth_metrics_stats, name='auth_metrics_stats'),
    
    # New device and application statistics endpoints
    path('api/statistics/devices/', DeviceStatisticsView.as_view(), name='device_statistics'),
    path('api/statistics/browsers/', BrowserStatisticsView.as_view(), name='browser_statistics'),
    path('api/statistics/operating-systems/', OSStatisticsView.as_view(), name='os_statistics'),
    path('api/statistics/applications/', ApplicationStatisticsView.as_view(), name='application_statistics'),
    path('api/statistics/locations/', LocationStatisticsView.as_view(), name='location_statistics'),
    path('api/statistics/outcomes/', OutcomeStatisticsView.as_view(), name='outcome_statistics'),
    path('api/statistics/event-activity/', EventActivityStatisticsView.as_view(), name='event_activity_statistics'),
    path('api/statistics/event-distribution/', EventDistributionStatisticsView.as_view(), name='event_distribution_statistics'),
    path('api/statistics/recent-events/', RecentEventsView.as_view(), name='recent_events'),
    path('api/statistics/all/', AllStatisticsView.as_view(), name='all_statistics'),
    
    # Diagnostic endpoints
    path('api/diagnostic/mongodb-status/', mongodb_status, name='mongodb_status'),
]