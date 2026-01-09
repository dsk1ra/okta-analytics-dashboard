"""
App configuration for analytics app.
"""
import logging
import threading
import time
from django.apps import AppConfig

logger = logging.getLogger(__name__)


class AnalyticsConfig(AppConfig):
    """
    Configuration class for the analytics application.
    """
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.analytics"
    
    def ready(self):
        """
        Perform initialization when Django starts.
        Imports signals and warms cache for instant performance.
        """
        import apps.analytics.signals  # noqa
        
        # Auto-warm cache on startup for instant fast performance
        try:
            from apps.analytics.services.login_statistics import (
                get_total_events_with_comparison,
            )
            from apps.analytics.services.metrics_optimized import (
                get_metrics_aggregation,
            )
            
            def warm_cache():
                try:
                    logger.info("Auto-warming cache on startup...")
                    start = time.time()
                    
                    # Warm quick statistics (these are used most frequently)
                    get_total_events_with_comparison(7, 7)
                    get_total_events_with_comparison(30, 30)
                    get_metrics_aggregation(7)
                    get_metrics_aggregation(30)
                    
                    elapsed = time.time() - start
                    logger.info(f"Cache warmed in {elapsed:.2f}s")
                except Exception as e:
                    logger.debug(f"Cache warming in background: {e}")
            
            # Start warming in background (wait 2 seconds for DB to be ready)
            thread = threading.Thread(target=lambda: (time.sleep(2), warm_cache()), daemon=True)
            thread.start()
            
        except Exception as e:
            logger.debug(f"Could not set up cache warming: {e}")
        

        # Register post migration signal handler to set up scheduled tasks
        # This ensures database operations happen after app initialization
        from django.db.models.signals import post_migrate
        from apps.analytics.scheduler import setup_scheduled_tasks
        
        # Connect the setup function to the post_migrate signal
        post_migrate.connect(setup_scheduled_tasks, sender=self)