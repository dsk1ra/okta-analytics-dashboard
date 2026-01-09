from django.apps import AppConfig


class OktaIntegrationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.okta_integration'
    verbose_name = 'Okta Integration'
    
    def ready(self):
        """
        Perform initialization when Django starts.
        """
        # Import any signals if needed
        pass