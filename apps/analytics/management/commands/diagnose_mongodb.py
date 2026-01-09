"""
Management command to diagnose MongoDB data structure and content.
Helps troubleshoot why metrics are showing as 0.
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from core.services.database import DatabaseService
import json
from datetime import datetime, timedelta


class Command(BaseCommand):
    help = 'Diagnose MongoDB okta_logs collection structure and content'

    def add_arguments(self, parser):
        parser.add_argument(
            '--db-name',
            type=str,
            default='OktaDashboardDB',
            help='MongoDB database name'
        )
        parser.add_argument(
            '--collection',
            type=str,
            default='okta_logs',
            help='MongoDB collection name'
        )

    def handle(self, *args, **options):
        db_name = options['db_name']
        collection_name = options['collection']
        
        self.stdout.write(self.style.SUCCESS(f"\n=== MongoDB Diagnostics ===\n"))
        self.stdout.write(f"Database: {db_name}")
        self.stdout.write(f"Collection: {collection_name}\n")
        
        try:
            # Connect to MongoDB
            db_service = DatabaseService()
            if not db_service.is_connected():
                self.stdout.write(self.style.ERROR("❌ Not connected to MongoDB"))
                return
            
            self.stdout.write(self.style.SUCCESS("✓ Connected to MongoDB"))
            
            # Get collection
            collection = db_service.get_collection(db_name, collection_name)
            
            # 1. Count documents
            total_count = collection.count_documents({})
            self.stdout.write(f"\n1. Total documents: {total_count}")
            
            if total_count == 0:
                self.stdout.write(self.style.WARNING("⚠️  No documents in collection!"))
                self.stdout.write("Available collections:")
                client = db_service.get_client()
                db = client[db_name]
                for coll_name in db.list_collection_names():
                    count = db[coll_name].count_documents({})
                    self.stdout.write(f"   - {coll_name}: {count} documents")
                return
            
            # 2. Sample document
            self.stdout.write(f"\n2. Sample document (first doc):")
            sample_doc = collection.find_one({})
            if sample_doc:
                # Remove ObjectId for readability
                sample_doc.pop('_id', None)
                self.stdout.write(json.dumps(sample_doc, indent=2, default=str))
            
            # 3. Check field existence
            self.stdout.write(f"\n3. Field analysis:")
            sample_size = min(100, total_count)
            fields_found = set()
            
            for doc in collection.find().limit(sample_size):
                for key in doc.keys():
                    if key != '_id':
                        fields_found.add(key)
            
            self.stdout.write(f"Fields found (in first {sample_size} docs):")
            for field in sorted(fields_found):
                self.stdout.write(f"   - {field}")
            
            # 4. Check eventType values
            self.stdout.write(f"\n4. Event types (sample of unique values):")
            event_types = collection.distinct('eventType')
            self.stdout.write(f"Total unique eventTypes: {len(event_types)}")
            self.stdout.write("Sample eventTypes:")
            for et in sorted(event_types)[:20]:
                count = collection.count_documents({'eventType': et})
                self.stdout.write(f"   - {et}: {count}")
            
            # 5. Check date range
            self.stdout.write(f"\n5. Date range analysis:")
            self.stdout.write("Checking 'published' field...")
            
            # Find earliest and latest
            earliest = collection.find_one(
                {'published': {'$exists': True}},
                sort=[('published', 1)]
            )
            latest = collection.find_one(
                {'published': {'$exists': True}},
                sort=[('published', -1)]
            )
            
            if earliest and latest:
                earliest_date = earliest.get('published', 'N/A')
                latest_date = latest.get('published', 'N/A')
                self.stdout.write(f"   Earliest: {earliest_date}")
                self.stdout.write(f"   Latest: {latest_date}")
            else:
                self.stdout.write("   ⚠️  No 'published' field found")
            
            # 6. Test queries
            self.stdout.write(f"\n6. Test queries:")
            
            # All events from last 30 days
            now = datetime.utcnow()
            thirty_days_ago = now - timedelta(days=30)
            cutoff_iso = thirty_days_ago.isoformat() + 'Z'
            
            query = {'published': {'$gte': cutoff_iso}}
            count = collection.count_documents(query)
            self.stdout.write(f"   Events from last 30 days: {count}")
            
            # user.session.start SUCCESS
            query = {
                'eventType': 'user.session.start',
                'outcome.result': 'SUCCESS'
            }
            count = collection.count_documents(query)
            self.stdout.write(f"   user.session.start SUCCESS (all time): {count}")
            
            # user.session.start SUCCESS in last 30 days
            query = {
                'eventType': 'user.session.start',
                'outcome.result': 'SUCCESS',
                'published': {'$gte': cutoff_iso}
            }
            count = collection.count_documents(query)
            self.stdout.write(f"   user.session.start SUCCESS (30 days): {count}")
            
            # Auth events
            query = {
                'eventType': {'$in': [
                    'user.authentication.auth_via_mfa',
                    'user.authentication.sso',
                    'user.session.start'
                ]},
                'published': {'$gte': cutoff_iso}
            }
            count = collection.count_documents(query)
            self.stdout.write(f"   Auth events (30 days): {count}")
            
            # Security events
            query = {
                'eventType': {'$regex': 'security|threat'},
                'published': {'$gte': cutoff_iso}
            }
            count = collection.count_documents(query)
            self.stdout.write(f"   Security events (30 days): {count}")
            
            # 7. Check authenticationContext
            self.stdout.write(f"\n7. Authentication context:")
            has_auth_context = collection.count_documents({
                'authenticationContext': {'$exists': True}
            })
            self.stdout.write(f"   Documents with authenticationContext: {has_auth_context}")
            
            has_root_session = collection.count_documents({
                'authenticationContext.rootSessionId': {'$exists': True}
            })
            self.stdout.write(f"   Documents with rootSessionId: {has_root_session}")
            
            # Show sample auth context
            doc_with_auth = collection.find_one({
                'authenticationContext': {'$exists': True}
            })
            if doc_with_auth:
                self.stdout.write("   Sample authenticationContext:")
                auth_ctx = doc_with_auth.get('authenticationContext', {})
                self.stdout.write(json.dumps(auth_ctx, indent=4, default=str))
            
            self.stdout.write(self.style.SUCCESS("\n✓ Diagnostics complete\n"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Error: {str(e)}"))
            import traceback
            traceback.print_exc()
