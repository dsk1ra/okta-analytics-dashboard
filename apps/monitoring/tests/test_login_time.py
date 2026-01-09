# login_tracking/tests/test_login_time.py
from django.test import TestCase
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import pytz

from apps.monitoring.utils import compute_avg_okta_login_time_from_mongo

class ComputeAvgLoginTimeTest(TestCase):
    @patch('apps.monitoring.utils.DatabaseService')
    def test_reverse_order_pairing(self, mock_db_service):
        base = datetime(2025,5,1,12,0,0, tzinfo=pytz.UTC)
        logs = [
            # auth_via_mfa then session.start ⇒ should compute +5 s
            {
                "eventType":"user.authentication.auth_via_mfa",
                "actor":{"id":"u"},
                "published": base.isoformat().replace('+00:00', 'Z'),
                "authenticationContext": {"rootSessionId": "sid123"}
            },
            {
                "eventType":"user.session.start",
                "actor":{"id":"u"},
                "published": (base+timedelta(seconds=5)).isoformat().replace('+00:00', 'Z'),
                "authenticationContext": {"rootSessionId": "sid123"}
            },
        ]
        mock_db = MagicMock()
        mock_db.get_collection.return_value.find.return_value.sort.return_value = logs
        mock_db_service.return_value = mock_db

        self.assertEqual(
            compute_avg_okta_login_time_from_mongo(days=1),
            5000.0
        )

class ComputeAvgLoginTimeEdgeCases(TestCase):
    def make_logs(self, entries):
        return entries

    @patch('apps.monitoring.utils.DatabaseService')
    def test_no_pairs(self, mock_db_service):
        mock_db = MagicMock()
        mock_db.get_collection.return_value.find.return_value.sort.return_value = []
        mock_db_service.return_value = mock_db

        avg = compute_avg_okta_login_time_from_mongo(days=1)
        self.assertIsNone(avg)

    @patch('apps.monitoring.utils.DatabaseService')
    def test_only_authorize(self, mock_db_service):
        one_auth = [
            {"eventType": "app.oauth2.authorize.code", "actor": {"id": "user1"},
             "_published_date": datetime(2025,5,1,12,0,0,tzinfo=pytz.UTC)}
        ]
        mock_db = MagicMock()
        mock_db.get_collection.return_value.find.return_value.sort.return_value = one_auth
        mock_db_service.return_value = mock_db

        avg = compute_avg_okta_login_time_from_mongo(days=1)
        self.assertIsNone(avg)
