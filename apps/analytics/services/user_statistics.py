"""
User statistics service for calculating user-related metrics from Okta logs.
"""
from core.services.database import DatabaseService
from datetime import datetime, timedelta, timezone
import logging

logger = logging.getLogger(__name__)


class UserStatisticsService:
    """Service for calculating user statistics from Okta logs"""
    
    def __init__(self):
        self.db_service = DatabaseService()
        # Get the collection directly - use correct database name
        self.collection = self.db_service.get_collection('OktaDashboardDB', 'okta_logs')
    
    def get_user_statistics(self, days=30):
        """
        Calculate comprehensive user statistics from Okta logs.
        
        Args:
            days: Number of days to look back for statistics
            
        Returns:
            dict: Dictionary containing user statistics
        """
        try:
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            
            # Get all unique users from the logs
            pipeline = [
                {
                    '$match': {
                        'published': {
                            '$gte': start_date.isoformat(),
                            '$lte': end_date.isoformat()
                        }
                    }
                },
                {
                    '$group': {
                        '_id': '$actor.alternateId',
                        'displayName': {'$first': '$actor.displayName'},
                        'eventCount': {'$sum': 1},
                        'lastActivity': {'$max': '$published'},
                        'successCount': {
                            '$sum': {
                                '$cond': [
                                    {'$eq': ['$outcome.result', 'SUCCESS']},
                                    1,
                                    0
                                ]
                            }
                        },
                        'failureCount': {
                            '$sum': {
                                '$cond': [
                                    {'$eq': ['$outcome.result', 'FAILURE']},
                                    1,
                                    0
                                ]
                            }
                        }
                    }
                },
                {
                    '$project': {
                        'id': '$_id',
                        'displayName': 1,
                        'eventCount': 1,
                        'lastActivity': 1,
                        'successCount': 1,
                        'failureCount': 1,
                        'failureRate': {
                            '$cond': [
                                {'$gt': ['$eventCount', 0]},
                                {
                                    '$multiply': [
                                        {'$divide': ['$failureCount', '$eventCount']},
                                        100
                                    ]
                                },
                                0
                            ]
                        }
                    }
                }
            ]
            
            users = list(self.collection.aggregate(pipeline))
            
            # Calculate statistics
            total_users = len(users)
            
            # Consider users active if they have activity in the last 7 days
            active_threshold = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            active_users = len([u for u in users if u.get('lastActivity', '') >= active_threshold])
            inactive_users = total_users - active_users
            
            # Calculate MFA enabled users (users with mfa-related events)
            mfa_pipeline = [
                {
                    '$match': {
                        'published': {
                            '$gte': start_date.isoformat(),
                            '$lte': end_date.isoformat()
                        },
                        '$or': [
                            {'eventType': {'$regex': 'mfa', '$options': 'i'}},
                            {'displayMessage': {'$regex': 'factor', '$options': 'i'}}
                        ]
                    }
                },
                {
                    '$group': {
                        '_id': '$actor.alternateId'
                    }
                }
            ]
            
            users_with_mfa = len(list(self.collection.aggregate(mfa_pipeline)))
            
            # Calculate locked accounts (users with account lock events)
            locked_pipeline = [
                {
                    '$match': {
                        'published': {
                            '$gte': start_date.isoformat(),
                            '$lte': end_date.isoformat()
                        },
                        '$or': [
                            {'eventType': {'$regex': 'user.account.lock', '$options': 'i'}},
                            {'displayMessage': {'$regex': 'locked', '$options': 'i'}},
                            {'outcome.result': 'FAILURE', 'displayMessage': {'$regex': 'locked|suspended', '$options': 'i'}}
                        ]
                    }
                },
                {
                    '$group': {
                        '_id': '$actor.alternateId'
                    }
                }
            ]
            
            locked_accounts = len(list(self.collection.aggregate(locked_pipeline)))
            
            # Calculate risk scores based on failure rates
            user_risk_high = len([u for u in users if u.get('failureRate', 0) > 30])
            user_risk_medium = len([u for u in users if 10 < u.get('failureRate', 0) <= 30])
            user_risk_low = total_users - user_risk_high - user_risk_medium
            
            # Get top active users
            top_active_users = sorted(
                users,
                key=lambda x: x.get('eventCount', 0),
                reverse=True
            )[:5]
            
            # Get suspicious users (high failure rate)
            suspicious_users = sorted(
                [u for u in users if u.get('failureRate', 0) > 20],
                key=lambda x: x.get('failureRate', 0),
                reverse=True
            )[:5]
            
            # Get recently active users
            recent_users = sorted(
                users,
                key=lambda x: x.get('lastActivity', ''),
                reverse=True
            )[:10]
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
                'users_with_mfa': users_with_mfa,
                'locked_accounts': locked_accounts,
                'user_risk_high': user_risk_high,
                'user_risk_medium': user_risk_medium,
                'user_risk_low': user_risk_low,
                'top_active_users': top_active_users,
                'suspicious_users': suspicious_users,
                'recent_users': recent_users,
                'days': days
            }
            
        except Exception as e:
            logger.error(f"Error calculating user statistics: {e}")
            return {
                'total_users': 0,
                'active_users': 0,
                'inactive_users': 0,
                'users_with_mfa': 0,
                'locked_accounts': 0,
                'user_risk_high': 0,
                'user_risk_medium': 0,
                'user_risk_low': 0,
                'top_active_users': [],
                'suspicious_users': [],
                'recent_users': [],
                'days': days
            }
