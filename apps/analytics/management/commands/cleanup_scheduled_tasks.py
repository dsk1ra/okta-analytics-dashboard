from django.core.management.base import BaseCommand
from django_q.models import Schedule
from django.apps import apps
import importlib
import inspect
import logging
import sys

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Cleans up all scheduled tasks in Django-Q and registers all required tasks'

    def handle(self, *args, **options):
        # Get count before deletion
        task_count = Schedule.objects.count()
        self.stdout.write(f"Found {task_count} scheduled tasks before cleanup")
        
        # Delete all scheduled tasks
        Schedule.objects.all().delete()
        self.stdout.write(self.style.SUCCESS(f"Successfully deleted {task_count} scheduled tasks"))
        
        # Get count after deletion to confirm
        remaining = Schedule.objects.count()
        self.stdout.write(f"Remaining scheduled tasks: {remaining}")
        
        # Register all scheduled tasks from all apps
        self.register_all_scheduled_tasks()
        
        # Get final count
        final_count = Schedule.objects.count()
        self.stdout.write(self.style.SUCCESS(f"Successfully registered {final_count} new scheduled tasks"))
    
    def register_all_scheduled_tasks(self):
        """
        Search through all apps and register their scheduled tasks
        """
        task_registration_count = 0
        
        # First register traffic_analysis scheduled tasks which include the Okta logs fetch
        try:
            from apps.analytics.scheduler import register_scheduled_tasks
            register_scheduled_tasks()
            self.stdout.write("Registered traffic_analysis scheduled tasks")
            task_registration_count += 1
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error registering traffic_analysis tasks: {str(e)}"))
        
        # Check for scheduler modules in all installed apps
        installed_apps = [app_config.name for app_config in apps.get_app_configs()]
        for app_name in installed_apps:
            if app_name == 'traffic_analysis':
                # Already handled above
                continue
                
            try:
                # Try to import the app's scheduler module
                scheduler_module = importlib.import_module(f"{app_name}.scheduler")
                
                # Look for register_scheduled_tasks function
                if hasattr(scheduler_module, 'register_scheduled_tasks'):
                    scheduler_module.register_scheduled_tasks()
                    self.stdout.write(f"Registered {app_name} scheduled tasks")
                    task_registration_count += 1
            except ImportError:
                # App doesn't have a scheduler module - that's fine
                pass
            except Exception as e:
                self.stdout.write(self.style.WARNING(f"Error loading scheduler for {app_name}: {str(e)}"))
        
        # Check login_tracking app specifically (if it exists but doesn't have a standard scheduler module)
        try:
            if 'login_tracking' in installed_apps:
                # Check if there's a specific scheduler function
                try:
                    from login_tracking import scheduler
                    if hasattr(scheduler, 'register_tasks'):
                        scheduler.register_tasks()
                        self.stdout.write("Registered login_tracking scheduled tasks")
                        task_registration_count += 1
                except ImportError:
                    pass
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Error registering login_tracking tasks: {str(e)}"))
            
        # Check TrafficAnalysis app specifically (if it exists but doesn't have a standard scheduler module)
        try:
            if 'TrafficAnalysis' in installed_apps:
                # Check if there's a specific scheduler function
                try:
                    from TrafficAnalysis import tasks
                    if hasattr(tasks, 'register_tasks'):
                        tasks.register_tasks()
                        self.stdout.write("Registered TrafficAnalysis scheduled tasks")
                        task_registration_count += 1
                except ImportError:
                    pass
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Error registering TrafficAnalysis tasks: {str(e)}"))
            
        self.stdout.write(f"Task registration process completed - registered {task_registration_count} app(s) tasks")