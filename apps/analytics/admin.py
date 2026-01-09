"""
Admin interface configuration for the traffic_analysis app.
"""
from django.contrib import admin
from apps.analytics.models import DashboardConfiguration


@admin.register(DashboardConfiguration)
class DashboardConfigurationAdmin(admin.ModelAdmin):
    """Admin interface for DashboardConfiguration model."""
    list_display = ('name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    ordering = ('-updated_at',)