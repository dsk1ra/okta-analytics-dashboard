import logging
import sys
from datetime import datetime
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.conf import settings
from pymongo import MongoClient
from core.services.database import DatabaseService

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Fetches Okta logs since the timestamp of the last log in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--fallback-minutes',
            type=int,
            default=15,
            help='Fallback minutes to fetch if no logs are found'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of logs to fetch per request (max 1000)'
        )
        parser.add_argument(
            '--debug',
            action='store_true',
            default=False,
            help='Enable debug output'
        )

    def handle(self, *args, **options):
        fallback_minutes = options['fallback_minutes']
        limit = min(options['limit'], 1000)  # Okta API max limit is 1000
        debug = options['debug']
        
        try:
            # Connect to MongoDB
            db_service = DatabaseService()
            if not db_service.is_connected():
                self.stdout.write(self.style.ERROR("Failed to connect to MongoDB. Using fallback time period."))
                # Call the original command with fallback minutes
                self._call_with_fallback(fallback_minutes, limit, debug)
                return
            
            # Get MongoDB client
            mongo_client = db_service.get_client()
            
            # Get MongoDB settings from Django settings
            mongo_settings = settings.MONGODB_SETTINGS
            db_name = mongo_settings.get('db', 'okta_dashboard')
            collection_name = 'okta_logs'
            
            # Get the collection
            logs_collection = mongo_client[db_name][collection_name]
            
            # Find the most recent log by published timestamp
            latest_log = logs_collection.find_one(
                {}, 
                sort=[("published", -1)]
            )
            
            if debug and latest_log:
                self.stdout.write(f"Latest log UUID: {latest_log.get('uuid')}")
                self.stdout.write(f"Latest log timestamp: {latest_log.get('published')}")
            
            if latest_log and 'published' in latest_log:
                # Use the timestamp from the latest log
                since_param = latest_log['published']
                self.stdout.write(self.style.SUCCESS(f"Found latest log with timestamp: {since_param}"))
                
                # Call the fetch_okta_logs_dpop command with the since parameter
                call_command(
                    'fetch_okta_logs_dpop',
                    since=since_param,
                    limit=limit,
                    debug=debug
                )
            else:
                self.stdout.write(self.style.WARNING("No logs found in MongoDB. Using fallback time period."))
                # Call with fallback minutes
                self._call_with_fallback(fallback_minutes, limit, debug)
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error fetching logs since last timestamp: {str(e)}"))
            if debug:
                import traceback
                traceback.print_exc()
    
    def _call_with_fallback(self, minutes, limit, debug):
        """Call fetch_okta_logs_dpop with fallback minutes"""
        self.stdout.write(f"Fetching logs from the last {minutes} minutes")
        call_command(
            'fetch_okta_logs_dpop',
            minutes=minutes,
            limit=limit,
            debug=debug
        )