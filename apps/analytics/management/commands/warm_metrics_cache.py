"""
Management command to warm up metrics-specific cache.
Run with: python manage.py warm_metrics_cache
"""
from django.core.management.base import BaseCommand
from apps.analytics.services.metrics_service import get_metrics_data
import logging
import time

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Warm up Redis cache with metrics dashboard data'

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
        
        self.stdout.write(self.style.WARNING(f'\nWarming metrics cache for periods: {periods} days\n'))
        
        start_time = time.time()
        success_count = 0
        error_count = 0
        
        # Warm up metrics for each period
        for days in periods:
            try:
                self.stdout.write(f'  Warming: Metrics Data ({days} days)... ', ending='')
                result = get_metrics_data(days)
                # Check if we got real data
                if result and result.get('auth_success_rate', 0) > 0:
                    self.stdout.write(self.style.SUCCESS(f'✓ (Auth Rate: {result.get("auth_success_rate", 0)}%)'))
                else:
                    self.stdout.write(self.style.WARNING(f'⚠ Default data returned'))
                success_count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'✗ Error: {str(e)}'))
                error_count += 1
                logger.error(f"Error warming metrics for {days} days: {str(e)}", exc_info=True)
        
        elapsed_time = time.time() - start_time
        
        self.stdout.write(self.style.SUCCESS(f'\n✓ Metrics cache warming completed in {elapsed_time:.2f} seconds'))
        self.stdout.write(f'  Success: {success_count}')
        if error_count > 0:
            self.stdout.write(self.style.ERROR(f'  Errors: {error_count}'))
        
        self.stdout.write(self.style.WARNING('\nCache TTL: 600 seconds (10 minutes)'))
        self.stdout.write('The /metrics page will now load from cache.')
