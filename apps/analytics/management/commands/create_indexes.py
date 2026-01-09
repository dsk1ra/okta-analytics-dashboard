"""
Management command to create MongoDB indexes for optimizing queries.
Run with: python manage.py create_indexes
"""
from django.core.management.base import BaseCommand
from pymongo import ASCENDING, DESCENDING, IndexModel
from core.services.database import DatabaseService
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Create MongoDB indexes for okta_logs collection to optimize queries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--drop-existing',
            action='store_true',
            help='Drop existing indexes before creating new ones (use with caution)',
        )
        parser.add_argument(
            '--target',
            type=str,
            default='real',
            choices=['real', 'sample', 'both'],
            help='Target database to create indexes in (real, sample, or both)',
        )

    def handle(self, *args, **options):
        drop_existing = options['drop_existing']
        target = options['target']
        
        db_service = DatabaseService()
        
        # Determine which databases to process
        targets = []
        if target in ['real', 'both']:
            targets.append(('OktaDashboardDB', 'Real'))
        if target in ['sample', 'both']:
            targets.append(('OktaDashboardSampleDB', 'Sample'))
        
        for db_name, label in targets:
            self.stdout.write(f"\n{self.style.WARNING(f'Processing {label} Database: {db_name}')}")
            self.create_indexes_for_db(db_service, db_name, drop_existing)

    def create_indexes_for_db(self, db_service, db_name, drop_existing):
        """Create indexes for a specific database."""
        try:
            collection = db_service.get_collection(db_name, 'okta_logs')
            
            # Drop existing indexes if requested (except _id)
            if drop_existing:
                self.stdout.write(self.style.WARNING('Dropping existing indexes...'))
                existing = collection.index_information()
                for index_name in existing:
                    if index_name != '_id_':
                        collection.drop_index(index_name)
                        self.stdout.write(f'  Dropped: {index_name}')
            
            # Define indexes to create
            indexes = [
                # Compound index for date range + event type queries (most common)
                IndexModel(
                    [('published', ASCENDING), ('eventType', ASCENDING)],
                    name='published_eventType_idx',
                    background=True
                ),
                
                # Compound index for date + outcome queries (login success/failure)
                IndexModel(
                    [('published', ASCENDING), ('outcome.result', ASCENDING)],
                    name='published_outcome_idx',
                    background=True
                ),
                
                # Compound index for event type + date (alternative query pattern)
                IndexModel(
                    [('eventType', ASCENDING), ('published', ASCENDING)],
                    name='eventType_published_idx',
                    background=True
                ),
                
                # Compound index for full statistics queries
                IndexModel(
                    [
                        ('published', ASCENDING),
                        ('eventType', ASCENDING),
                        ('outcome.result', ASCENDING)
                    ],
                    name='published_eventType_outcome_idx',
                    background=True
                ),
                
                # Index for actor queries (user-based filtering)
                IndexModel(
                    [('actor.id', ASCENDING), ('published', DESCENDING)],
                    name='actor_published_idx',
                    background=True
                ),
                
                # Index for client IP queries
                IndexModel(
                    [('client.ipAddress', ASCENDING), ('published', DESCENDING)],
                    name='client_ip_published_idx',
                    background=True
                ),
            ]
            
            # Create indexes
            self.stdout.write(self.style.SUCCESS('\nCreating indexes...'))
            result = collection.create_indexes(indexes)
            
            self.stdout.write(self.style.SUCCESS(f'\nSuccessfully created {len(result)} indexes:'))
            for index_name in result:
                self.stdout.write(f'  ✓ {index_name}')
            
            # Show index information
            self.stdout.write(self.style.WARNING('\nCurrent indexes:'))
            for index_name, index_info in collection.index_information().items():
                key_spec = index_info.get('key', [])
                key_str = ', '.join([f"{k}:{v}" for k, v in key_spec])
                self.stdout.write(f'  {index_name}: [{key_str}]')
            
            # Get collection stats
            client = db_service.get_client()
            db = client[db_name]
            stats = db.command('collStats', 'okta_logs')
            doc_count = stats.get('count', 0)
            avg_doc_size = stats.get('avgObjSize', 0)
            total_size = stats.get('size', 0)
            
            self.stdout.write(self.style.SUCCESS(f'\nCollection Statistics:'))
            self.stdout.write(f'  Documents: {doc_count:,}')
            self.stdout.write(f'  Avg Size: {avg_doc_size:,} bytes')
            self.stdout.write(f'  Total Size: {total_size / 1024 / 1024:.2f} MB')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating indexes: {str(e)}')
            )
            logger.error(f"Error creating indexes: {str(e)}", exc_info=True)
