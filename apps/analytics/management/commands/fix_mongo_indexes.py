"""
Management command to fix MongoDB index conflicts.

Usage:
    python manage.py fix_mongo_indexes
"""
from django.core.management.base import BaseCommand
from pymongo import MongoClient
from django.conf import settings
import logging

class Command(BaseCommand):
    help = 'Fixes MongoDB index conflicts by dropping problematic indexes'

    def handle(self, *args, **options):
        try:
            # Get MongoDB connection details from settings
            mongo_uri = getattr(settings, 'MONGODB_URI', 'mongodb://localhost:27017')
            db_name = getattr(settings, 'MONGODB_NAME', 'okta_dashboard')
            
            self.stdout.write(self.style.NOTICE(f"Connecting to MongoDB at {mongo_uri}"))
            
            # Connect to MongoDB directly using PyMongo
            client = MongoClient(mongo_uri)
            db = client[db_name]
            
            # Get the okta_events collection
            okta_events_collection = db['okta_events']
            
            # List all indexes before changes
            self.stdout.write("Current indexes in okta_events collection:")
            index_info = okta_events_collection.index_information()
            for name, info in index_info.items():
                self.stdout.write(f"  - {name}: {info}")
            
            # Check if the problematic index exists
            if any('target_published_idx' in idx for idx in index_info.values()):
                self.stdout.write(self.style.WARNING("Found problematic index 'target_published_idx'"))
                
                # Drop the problematic index
                try:
                    okta_events_collection.drop_index('target_published_idx')
                    self.stdout.write(self.style.SUCCESS("Successfully dropped 'target_published_idx'"))
                except Exception as e:
                    # Try dropping by finding the actual index name
                    for name, info in index_info.items():
                        if 'name' in info and info['name'] == 'target_published_idx':
                            okta_events_collection.drop_index(name)
                            self.stdout.write(self.style.SUCCESS(f"Successfully dropped index named '{name}'"))
                            break
            else:
                self.stdout.write(self.style.SUCCESS("No problematic index found"))
            
            # Show indexes after changes
            self.stdout.write("Indexes after fixing conflicts:")
            for name, info in okta_events_collection.index_information().items():
                self.stdout.write(f"  - {name}: {info}")
            
            self.stdout.write(self.style.SUCCESS("MongoDB index conflicts resolved"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error fixing MongoDB indexes: {str(e)}"))
            logging.exception("Failed to fix MongoDB indexes")