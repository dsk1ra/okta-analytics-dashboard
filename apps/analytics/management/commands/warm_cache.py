"""
Management command to warm up Redis cache with common statistics queries.
Run with: python manage.py warm_cache
"""
from django.core.management.base import BaseCommand
from apps.analytics.services.login_statistics import (
    get_total_events_with_comparison,
    get_login_events_with_comparison,
    get_failed_login_with_comparison,
    get_security_events_with_comparison,
    get_event_activity,
    get_event_distribution,
)
import logging
import time

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Warm up Redis cache with common dashboard statistics queries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--periods',
            type=str,
            default='7,30,90',
            help='Comma-separated list of day periods to warm (default: 7,30,90)',
        )

    def handle(self, *args, **options):
        periods_str = options['periods']
        periods = [int(p.strip()) for p in periods_str.split(',')]
        
        self.stdout.write(self.style.WARNING(f'\nWarming cache for periods: {periods} days\n'))
        
        start_time = time.time()
        success_count = 0
        error_count = 0
        
        # Warm up comparison statistics (most common)
        for days in periods:
            queries = [
                ('Total Events', get_total_events_with_comparison, (days, days)),
                ('Login Events', get_login_events_with_comparison, (days, days)),
                ('Failed Logins', get_failed_login_with_comparison, (days, days)),
                ('Security Events', get_security_events_with_comparison, (days, days)),
            ]
            
            for name, func, args in queries:
                try:
                    self.stdout.write(f'  Warming: {name} ({days} days)... ', ending='')
                    result = func(*args)
                    self.stdout.write(self.style.SUCCESS(f'✓ ({result.get("current_count", 0)} events)'))
                    success_count += 1
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'✗ Error: {str(e)}'))
                    error_count += 1
                    logger.error(f"Error warming {name}: {str(e)}", exc_info=True)
        
        # Warm up activity charts (common periods)
        for days in [7, 14, 30]:
            try:
                self.stdout.write(f'  Warming: Event Activity ({days} days)... ', ending='')
                result = get_event_activity(days)
                total = sum(result.get('successful', []))
                self.stdout.write(self.style.SUCCESS(f'✓ ({total} events)'))
                success_count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ Error: {str(e)}'))
                error_count += 1
                logger.error(f"Error warming event activity: {str(e)}", exc_info=True)
        
        # Warm up distribution charts
        for days in [7, 30, 90]:
            try:
                self.stdout.write(f'  Warming: Event Distribution ({days} days)... ', ending='')
                result = get_event_distribution(days)
                total = sum(result.get('counts', []))
                self.stdout.write(self.style.SUCCESS(f'✓ ({total} events)'))
                success_count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ Error: {str(e)}'))
                error_count += 1
                logger.error(f"Error warming event distribution: {str(e)}", exc_info=True)
        
        elapsed_time = time.time() - start_time
        
        self.stdout.write(self.style.SUCCESS(f'\n✓ Cache warming completed in {elapsed_time:.2f} seconds'))
        self.stdout.write(f'  Success: {success_count}')
        if error_count > 0:
            self.stdout.write(self.style.ERROR(f'  Errors: {error_count}'))
        
        self.stdout.write(self.style.WARNING('\nCache TTL: 600 seconds (10 minutes)'))
        self.stdout.write('Run this command every 10 minutes to keep cache fresh.')
