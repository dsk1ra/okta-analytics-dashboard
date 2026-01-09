import logging
import argparse
from django.core.management.base import BaseCommand
from django.conf import settings
from datetime import datetime

# Fix the import path to use okta_dashboard.services instead of config.services
from core.services.okta_logs import OktaLogsClient

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Fetches Okta logs using DPoP authentication and stores them in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=0,
            help='Fetch logs from the last N days'
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=0,
            help='Fetch logs from the last N hours'
        )
        parser.add_argument(
            '--minutes',
            type=int,
            default=15,
            help='Fetch logs from the last N minutes'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of logs to fetch per request (max 1000)'
        )
        parser.add_argument(
            '--filter',
            type=str,
            help='Filter query for Okta logs (e.g. "eventType eq \"user.session.start\"")'
        )
        parser.add_argument(
            '--since',
            type=str,
            help='ISO8601 timestamp to fetch logs since (e.g. "2025-05-01T00:00:00.000Z")'
        )
        parser.add_argument(
            '--max-pages',
            type=int,
            default=10,
            help='Maximum number of pages to fetch (0 for unlimited)'
        )
        parser.add_argument(
            '--direct-mongo',
            action='store_true',
            default=False,
            help='Use direct MongoDB connection instead of DatabaseService'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help='Only fetch logs, do not store them in the database'
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            default=False,
            help='Enable debug output'
        )

    def handle(self, *args, **options):
        days = options['days']
        hours = options['hours']
        minutes = options['minutes']
        limit = min(options['limit'], 1000)  # Okta API max limit is 1000
        filter_query = options.get('filter')
        since_param = options.get('since')
        max_pages = options['max_pages']
        use_direct_mongo = options['direct_mongo']
        dry_run = options['dry_run']
        debug = options['debug']
        
        # Validate that Okta settings are configured
        org_url = settings.OKTA_ORG_URL
        client_id = settings.OKTA_CLIENT_ID
        
        # Validate required parameters
        if not org_url or not client_id:
            self.stdout.write(self.style.ERROR("ERROR: Missing required Okta configuration."))
            self.stdout.write(self.style.ERROR("Please set OKTA_ORG_URL and OKTA_CLIENT_ID in your settings.py or .env file."))
            return
        
        try:
            # Initialize the OktaLogsClient with the appropriate settings
            # By default, the client uses DatabaseService for MongoDB storage
            logs_client = OktaLogsClient(use_direct_mongodb=use_direct_mongo, debug=debug)
            
            # Log our operation
            self.stdout.write(f"Fetching Okta logs with limit {limit} and max pages {max_pages}")
            
            # Fetch logs by timeframe or by specific timestamp
            logs = []
            if since_param:
                self.stdout.write(f"Using provided since parameter: {since_param}")
                logs = logs_client.get_logs_since(
                    iso_timestamp=since_param,
                    limit=limit,
                    filter_query=filter_query,
                    max_pages=max_pages,
                    store_in_mongodb=not dry_run
                )
            else:
                self.stdout.write(f"Using timeframe: {days} days, {hours} hours, {minutes} minutes")
                logs = logs_client.get_logs_by_timeframe(
                    days=days,
                    hours=hours,
                    minutes=minutes,
                    limit=limit,
                    filter_query=filter_query,
                    max_pages=max_pages,
                    store_in_mongodb=not dry_run
                )
            
            # Summarize results
            total_logs = len(logs)
            self.stdout.write(self.style.SUCCESS(f"\nOperations complete. Retrieved {total_logs} logs."))
            
            if dry_run:
                self.stdout.write(self.style.WARNING("Dry run mode: logs were not stored in MongoDB"))
            else:
                self.stdout.write(self.style.SUCCESS(f"Logs stored in MongoDB using {'direct connection' if use_direct_mongo else 'DatabaseService'}"))
            
            # Provide a sample of the first log
            if logs:
                self.stdout.write("\nSample log entry:")
                sample_log = logs[0]
                sample_display = {
                    "uuid": sample_log.get("uuid"),
                    "eventType": sample_log.get("eventType"),
                    "severity": sample_log.get("severity"),
                    "displayMessage": sample_log.get("displayMessage"),
                    "published": sample_log.get("published"),
                    "outcome": sample_log.get("outcome"),
                }
                for key, value in sample_display.items():
                    self.stdout.write(f"  {key}: {value}")
            
            # Close the client connections
            logs_client.close()
            
        except Exception as e:
            error_msg = f"Error fetching Okta logs: {str(e)}"
            logger.error(error_msg)
            self.stdout.write(self.style.ERROR(error_msg))
            if debug:
                import traceback
                traceback.print_exc()