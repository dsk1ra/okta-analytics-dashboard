import os
import mongoengine
from django.conf import settings
import logging
from pymongo import MongoClient
import time
import environ

logger = logging.getLogger(__name__)
env = environ.Env()

# Import sample data service
try:
    from core.services.sample_data import SampleDataService
    HAS_SAMPLE_DATA = True
except ImportError:
    HAS_SAMPLE_DATA = False
    logger.warning("Sample data service not available")

"""Singleton MongoDB connection manager for application runtime."""
class DatabaseService:
    _instance = None
    _is_connected = False
    _connection = None
    _client = None
    _last_ping = 0
    _ping_interval = 60  # Check connection every 60 seconds

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._is_connected:
            self.connect()

    @classmethod
    def reset(cls):
        """Reset the singleton instance and disconnect any existing connections"""
        if cls._instance and cls._instance._client:
            cls._instance._client.close()
        
        # Clear mongoengine's connection registry
        mongoengine.disconnect_all()
        
        # Clear connection registry in mongoengine
        if hasattr(mongoengine.connection, '_connections'):
            mongoengine.connection._connections = {}
        if hasattr(mongoengine.connection, '_connection_settings'):
            mongoengine.connection._connection_settings = {}
        if hasattr(mongoengine.connection, '_dbs'):
            mongoengine.connection._dbs = {}
        
        # Reset instance variables
        cls._instance = None
        cls._is_connected = False
        cls._connection = None
        cls._client = None
        cls._last_ping = 0

    def connect(self):
        """Establish MongoDB connection with optimized pooling and reconnect support."""
        try:
            # Ensure any prior connections are fully cleaned up before reconnecting
            self.__class__.reset()
            
            # Prefer explicit connection string when provided
            mongo_url = env("MONGODB_URL", default=None)
            
            # Otherwise, construct URL from discrete settings
            if not mongo_url:
                mongo_host = settings.MONGODB_SETTINGS.get('host', 'localhost')
                mongo_port = settings.MONGODB_SETTINGS.get('port', 27017)
                mongo_db = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
                mongo_user = settings.MONGODB_SETTINGS.get('username')
                mongo_pass = settings.MONGODB_SETTINGS.get('password')
                
                # Log auth configuration without revealing secrets
                logger.debug(f"MongoDB Configuration: host={mongo_host}, port={mongo_port}, db={mongo_db}, user={'***' if mongo_pass else 'None'}")
                
                # Additional check for empty strings
                if mongo_user == '':
                    logger.warning("MongoDB username is an empty string")
                    mongo_user = None
                if mongo_pass == '':
                    logger.warning("MongoDB password is an empty string")
                    mongo_pass = None
                
                # Build connection URL
                if mongo_user and mongo_pass:
                    auth_part = f"{mongo_user}:{mongo_pass}@"
                else:
                    auth_part = ""
                    
                mongo_url = f"mongodb://{auth_part}{mongo_host}:{mongo_port}/{mongo_db}"
            
            # Configure connection pool settings
            pool_settings = {
                'maxPoolSize': settings.MONGODB_SETTINGS.get('maxPoolSize', 100),
                'minPoolSize': settings.MONGODB_SETTINGS.get('minPoolSize', 10),
                'maxIdleTimeMS': settings.MONGODB_SETTINGS.get('maxIdleTimeMS', 30000),
                'waitQueueTimeoutMS': settings.MONGODB_SETTINGS.get('waitQueueTimeoutMS', 5000),
                'socketTimeoutMS': settings.MONGODB_SETTINGS.get('socketTimeoutMS', 20000),
                'connectTimeoutMS': settings.MONGODB_SETTINGS.get('connectTimeoutMS', 10000),
                'serverSelectionTimeoutMS': settings.MONGODB_SETTINGS.get('serverSelectionTimeoutMS', 10000)
            }
            
            # Add pool settings to connection string if not SRV URI and no existing params
            if 'mongodb://' in mongo_url and '?' not in mongo_url:
                mongo_url += '?'
                params = []
                for key, value in pool_settings.items():
                    params.append(f"{key}={value}")
                mongo_url += '&'.join(params)
                
            # Log the connection URL without credentials for debugging
            safe_url = mongo_url
            if '@' in safe_url:
                safe_url = 'mongodb://' + safe_url.split('@')[1]
            logger.debug(f"Connecting to MongoDB with URL: {safe_url}")
            
            # Create MongoClient instance with connection pooling
            self._client = MongoClient(mongo_url)
            
            # Create mongoengine connection
            self._connection = mongoengine.connect(
                host=mongo_url,
                alias='default'
            )
            
            # Test connection
            self._client.admin.command('ping')
            self._last_ping = time.time()
            DatabaseService._is_connected = True
            logger.info("Successfully connected to MongoDB with optimized connection pool")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            DatabaseService._is_connected = False
            raise

    def is_connected(self):
        """Check if database is connected with connection refresh"""
        # Check if we should test the connection based on ping interval
        current_time = time.time()
        should_ping = (current_time - self._last_ping) > self._ping_interval
        
        if not self._is_connected or not self._connection or not self._client:
            return False
            
        if should_ping:
            try:
                # Test connection with a ping
                self._client.admin.command('ping')
                self._last_ping = current_time
                return True
            except Exception as e:
                logger.warning(f"MongoDB connection test failed: {e}")
                self._is_connected = False
                # Try to reconnect
                try:
                    logger.info("Attempting to reconnect to MongoDB")
                    self.connect()
                    return self._is_connected
                except Exception as reconnect_error:
                    logger.error(f"Failed to reconnect to MongoDB: {reconnect_error}")
                    return False
        return True

    def disconnect(self):
        """Disconnect from MongoDB"""
        if self._client:
            self._client.close()
        mongoengine.disconnect_all()
        self._connection = None
        self._client = None
        DatabaseService._is_connected = False
        logger.info("Disconnected from MongoDB")
        
    def get_client(self):
        """Get the raw MongoDB client for advanced operations"""
        if not self._is_connected:
            self.connect()
        return self._client
        
    def get_collection(self, db_name, collection_name):
        """Get a MongoDB collection with connection check, selecting DB by DATA_SOURCE."""
        # Determine effective database name based on DATA_SOURCE
        data_source = getattr(settings, 'DATA_SOURCE', 'real')
        if data_source == 'sample':
            effective_db = getattr(settings, 'MONGODB_SAMPLE_DB_NAME', settings.MONGODB_SETTINGS.get('db', db_name))
        else:
            effective_db = settings.MONGODB_SETTINGS.get('db', db_name)

        # Use real MongoDB connection
        if not self.is_connected():
            self.connect()
        return self._client[effective_db][collection_name]


class SampleCollection:
    """Wrapper class that mimics MongoDB collection behavior with sample data."""
    
    def __init__(self, db_name, collection_name):
        self.db_name = db_name
        self.collection_name = collection_name
    
    def find(self, filter_query=None, *args, **kwargs):
        """Mimic MongoDB find operation with sample data."""
        return SampleDataService.get_sample_collection(
            self.collection_name, 
            filter_query=filter_query
        )
    
    def find_one(self, filter_query=None, *args, **kwargs):
        """Mimic MongoDB find_one operation."""
        cursor = self.find(filter_query, *args, **kwargs)
        try:
            return next(iter(cursor))
        except StopIteration:
            return None
    
    def count_documents(self, filter_query=None, *args, **kwargs):
        """Mimic MongoDB count_documents operation."""
        cursor = self.find(filter_query, *args, **kwargs)
        return cursor.count()
    
    def aggregate(self, pipeline, *args, **kwargs):
        """Mimic MongoDB aggregate operation (basic support)."""
        # For now, return empty results for aggregate queries
        # This could be enhanced to support common aggregation patterns
        logger.warning(f"Aggregate query on sample data may not return accurate results")
        from core.services.sample_data import SampleCursor
        return SampleCursor([])
    
    def insert_many(self, documents, *args, **kwargs):
        """Mimic MongoDB insert_many operation (no-op for sample data)."""
        logger.warning(f"insert_many called on sample data collection - operation ignored")
        # Return a mock result object
        class MockInsertResult:
            def __init__(self, count):
                self.inserted_ids = [None] * count
        return MockInsertResult(len(documents))
    
    def delete_many(self, filter_query, *args, **kwargs):
        """Mimic MongoDB delete_many operation (no-op for sample data)."""
        logger.warning(f"delete_many called on sample data collection - operation ignored")
        # Return a mock result object
        class MockDeleteResult:
            def __init__(self):
                self.deleted_count = 0
        return MockDeleteResult()