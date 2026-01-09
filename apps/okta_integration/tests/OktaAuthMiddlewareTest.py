from django.test import TestCase, RequestFactory, Client
from django.urls import reverse
from django.contrib.sessions.middleware import SessionMiddleware
from unittest.mock import patch, MagicMock
from apps.okta_integration.middleware import OktaAuthMiddleware
from apps.okta_integration.views import login_view, callback_view, logout_view

class OktaAuthMiddlewareTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = OktaAuthMiddleware(lambda r: r)
    
    @patch('apps.okta_integration.middleware.requests.get')
    def test_valid_access_token(self, mock_get):
        # Mock successful response from Okta
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'email': 'test@example.com',
            'given_name': 'Test',
            'family_name': 'User'
        }
        mock_get.return_value = mock_response
        
        # Create request with session
        request = self.factory.get('/dashboard/')
        middleware = SessionMiddleware(lambda r: r)
        middleware.process_request(request)
        request.session['okta_access_token'] = 'valid_token'
        request.session.save()
        
        # Process request with middleware
        response = self.middleware(request)
        
        # Verify user is created and authenticated
        self.assertTrue(hasattr(request, 'user'))
        self.assertTrue(request.user.is_authenticated)
        self.assertEqual(request.user.username, 'test@example.com')

    @patch('apps.okta_integration.middleware.requests.get')
    def test_invalid_access_token(self, mock_get):
        # Mock failed response from Okta
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        # Create request with session
        request = self.factory.get('/dashboard/')
        middleware = SessionMiddleware(lambda r: r)
        middleware.process_request(request)
        request.session['okta_access_token'] = 'invalid_token'
        request.session.save()
        
        # Process request with middleware
        with patch('apps.okta_integration.middleware.redirect') as mock_redirect:
            mock_redirect.return_value = 'redirected'
            response = self.middleware(request)
            
            # Verify redirect to login
            mock_redirect.assert_called_once()
            self.assertEqual(response, 'redirected')
    
    @patch('apps.okta_integration.middleware.requests.get')
    def test_no_access_token(self, mock_get):
        # Create request with session but no token
        request = self.factory.get('/dashboard/')
        middleware = SessionMiddleware(lambda r: r)
        middleware.process_request(request)
        request.session.save()
        
        # Process request with middleware
        with patch('apps.okta_integration.middleware.redirect') as mock_redirect:
            mock_redirect.return_value = 'redirected'
            response = self.middleware(request)
            
            # Verify redirect to login
            mock_redirect.assert_called_once()
            self.assertEqual(response, 'redirected')

    def test_exempt_url(self):
        # Assuming '/health/' is an exempt URL
        request = self.factory.get('/health/')
        middleware = SessionMiddleware(lambda r: r)
        middleware.process_request(request)
        request.session.save()
        
        # Process request with middleware
        response = self.middleware(request)
        
        # Verify the request is passed through without redirect
        self.assertEqual(response, request)

class OktaViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
    
    @patch('apps.okta_integration.views.settings')
    def test_login_view(self, mock_settings):
        # Configure mock settings
        mock_settings.OKTA_CLIENT_ID = 'test_client_id'
        mock_settings.OKTA_SCOPES = 'openid profile email'
        mock_settings.OKTA_REDIRECT_URI = 'http://localhost:8000/okta/callback/'
        mock_settings.OKTA_AUTHORIZATION_ENDPOINT = 'https://test.okta.com/oauth2/default/v1/authorize'
        
        # Test login view redirects to Okta
        response = self.client.get(reverse('okta_login'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue('test.okta.com/oauth2/default/v1/authorize' in response.url)
        
        # Verify session contains state parameter
        self.assertTrue('okta_state' in self.client.session)

    @patch('apps.okta_integration.views.requests.post')
    def test_callback_view(self, mock_post):
        # Mock token response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'id_token': 'test_id_token'
        }
        mock_post.return_value = mock_response
        
        # Set up session with state
        session = self.client.session
        session['okta_state'] = 'test_state'
        session.save()
        
        # Mock user info retrieval
        with patch('apps.okta_integration.views.get_user_info') as mock_user_info:
            mock_user_info.return_value = {
                'email': 'test@example.com',
                'given_name': 'Test',
                'family_name': 'User'
            }
            
            # Test callback with valid state and code
            response = self.client.get(
                reverse('okta_callback'),
                {'code': 'test_code', 'state': 'test_state'}
            )
            
            self.assertEqual(response.status_code, 302)
            
            # Verify tokens are stored in session
            self.assertEqual(self.client.session['okta_access_token'], 'test_access_token')
            self.assertEqual(self.client.session['okta_refresh_token'], 'test_refresh_token')
            self.assertEqual(self.client.session['okta_id_token'], 'test_id_token')
    
    def test_logout_view(self):
        # Set up session with tokens
        session = self.client.session
        session['okta_access_token'] = 'test_token'
        session['okta_refresh_token'] = 'test_refresh'
        session['okta_id_token'] = 'test_id'
        session.save()
        
        # Test logout
        response = self.client.get(reverse('okta_logout'))
        
        # Verify tokens are removed from session
        self.assertNotIn('okta_access_token', self.client.session)
        self.assertNotIn('okta_refresh_token', self.client.session)
        self.assertNotIn('okta_id_token', self.client.session)
        
        # Verify redirect after logout
        self.assertEqual(response.status_code, 302)