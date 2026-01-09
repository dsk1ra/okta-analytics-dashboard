import json
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from core.services.database import DatabaseService
from core.services.okta_logs import OktaLogsClient
from datetime import datetime, timedelta

@require_GET
def mongodb_status(request):
    """
    Diagnostic view that checks MongoDB connection status and fetches recent logs.
    """
    result = {
        'timestamp': datetime.now().isoformat(),
        'mongodb_connection': {
            'status': 'unknown',
            'details': ''
        },
        'okta_logs': {
            'status': 'unknown',
            'count': 0,
            'details': '',
            'sample': None
        }
    }
    
    # Check MongoDB connection
    try:
        db_service = DatabaseService()
        is_connected = db_service.is_connected()
        
        result['mongodb_connection']['status'] = 'connected' if is_connected else 'disconnected'
        
        if is_connected:
            # Get available databases
            dbs = db_service.get_client().list_database_names()
            result['mongodb_connection']['details'] = f"Connected to MongoDB. Available databases: {dbs}"
            
            # Check for okta_logs collection
            logs_collection = db_service.get_collection('okta_dashboard', 'okta_logs')
            count = logs_collection.count_documents({})
            result['mongodb_connection']['collection_count'] = count
            
            # Test fetch recent logs from Okta and store in MongoDB
            try:
                # Fetch logs from the last hour
                logs_client = OktaLogsClient()
                
                # First check if we have logs in MongoDB
                one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
                db_logs = logs_client.get_logs_from_mongodb(
                    start_date=one_hour_ago,
                    limit=5
                )
                
                result['okta_logs']['status'] = 'retrieved'
                result['okta_logs']['count'] = len(db_logs)
                
                if db_logs:
                    # We have logs in MongoDB
                    result['okta_logs']['details'] = f"Found {len(db_logs)} recent logs in MongoDB"
                    result['okta_logs']['sample'] = db_logs[0]['eventType'] if db_logs else None
                else:
                    # Try to fetch logs from Okta API
                    result['okta_logs']['details'] = "No recent logs found in MongoDB, trying API fetch"
                    try:
                        # Fetch just 1 log to test the connection
                        api_logs = logs_client.get_logs_with_filter(
                            limit=1,
                            start_date=one_hour_ago,
                            store_in_mongodb=True
                        )
                        
                        result['okta_logs']['status'] = 'fetched'
                        result['okta_logs']['count'] = len(api_logs)
                        result['okta_logs']['details'] = f"Fetched {len(api_logs)} logs from Okta API"
                        result['okta_logs']['sample'] = api_logs[0]['eventType'] if api_logs else None
                    except Exception as api_error:
                        result['okta_logs']['status'] = 'error'
                        result['okta_logs']['details'] = f"Error fetching from API: {str(api_error)}"
                
            except Exception as e:
                result['okta_logs']['status'] = 'error'
                result['okta_logs']['details'] = str(e)
        else:
            result['mongodb_connection']['details'] = "Failed to connect to MongoDB"
    
    except Exception as e:
        result['mongodb_connection']['status'] = 'error'
        result['mongodb_connection']['details'] = str(e)
    
    return JsonResponse(result)