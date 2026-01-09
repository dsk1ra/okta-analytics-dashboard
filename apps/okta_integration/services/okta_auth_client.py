"""
Okta Authentication Client

This module provides a dedicated client for Okta user authentication operations 
using organization 72300026, separate from the logs fetching functionality.
"""
import logging
import requests
import time
import uuid
import jwt
import json
import hashlib
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional, Any
from django.conf import settings
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OktaAuthClient:
    """
    Authentication client specifically for Okta user authentication flows.
    
    This class handles only authentication operations (login, token exchange, etc.)
    and is completely separate from API/logs access functionality.
    It is specifically configured to use the authentication organization (72300026).
    """
    
    def __init__(self):
        """Initialize the Okta Authentication client with settings from Django configuration"""
        # Store authentication credentials for user flows - explicitly use auth org
        self.client_id = settings.OKTA_AUTHORIZATION_CLIENT_ID
        self.client_secret = settings.OKTA_AUTHORIZATION_CLIENT_SECRET
        self.org_url = settings.OKTA_AUTHORIZATION_ORG_URL
        
        # Derived endpoints for authentication flows
        self.authorization_endpoint = f"{self.org_url}/oauth2/v1/authorize"
        self.token_endpoint = f"{self.org_url}/oauth2/v1/token"
        self.userinfo_endpoint = f"{self.org_url}/oauth2/v1/userinfo"
        self.introspect_endpoint = f"{self.org_url}/oauth2/v1/introspect"
        
        # Common settings
        self.redirect_uri = settings.OKTA_REDIRECT_URI
        
        # Log important configuration details
        logger.info(f"OktaAuthClient initialized with auth organization: {self.org_url}")
        
        # Session for connection pooling and performance optimization
        self.session = self._create_optimized_session()
        
        # Load or generate RSA key pair for DPoP
        self._setup_key_pair()
    
    def _create_optimized_session(self) -> requests.Session:
        """Create and configure an optimized requests session with connection pooling"""
        session = requests.Session()
        
        # Configure connection pooling
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=2,
            pool_block=False
        )
        
        # Mount the adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _setup_key_pair(self):
        """Set up RSA key pairs for DPoP"""
        try:
            # Use the same private key that was registered with Okta
            private_key_path = os.path.join(settings.BASE_DIR, 'keys', 'private_key.pem')
            with open(private_key_path, 'rb') as key_file:
                private_key_data = key_file.read()
            
            self.private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None
            )
            logger.info("Successfully loaded the registered private key")
            
            # Generate a separate key for DPoP (security best practice)
            self.dpop_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Get public key in JWK format for DPoP
            dpop_public_key = self.dpop_private_key.public_key()
            dpop_public_numbers = dpop_public_key.public_numbers()
            
            # Convert to JWK format for DPoP
            self.dpop_jwk = {
                "kty": "RSA",
                "e": base64.urlsafe_b64encode(dpop_public_numbers.e.to_bytes((dpop_public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "n": base64.urlsafe_b64encode(dpop_public_numbers.n.to_bytes((dpop_public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "alg": "RS256",
                "use": "sig"
            }
            
        except Exception as e:
            logger.warning(f"Could not load registered private key: {e}. Generating new keys.")
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Use the same key for DPoP in this case
            self.dpop_private_key = self.private_key
            
            # Get public key in JWK format for DPoP
            dpop_public_key = self.dpop_private_key.public_key()
            dpop_public_numbers = dpop_public_key.public_numbers()
            
            # Convert to JWK format for DPoP
            self.dpop_jwk = {
                "kty": "RSA",
                "e": base64.urlsafe_b64encode(dpop_public_numbers.e.to_bytes((dpop_public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "n": base64.urlsafe_b64encode(dpop_public_numbers.n.to_bytes((dpop_public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "alg": "RS256",
                "use": "sig"
            }
    
    def _normalize_url_for_dpop(self, http_method: str, url: str) -> str:
        """
        Normalize URL for DPoP proof as per Okta requirements
        
        Args:
            http_method: HTTP method
            url: The original URL
            
        Returns:
            Normalized URL for DPoP proof
        """
        parsed_url = urlparse(url)
        
        # Use full URL for token endpoint to satisfy Okta DPoP expectations
        normalized_url = url
        logger.debug(f"Using full URL for endpoint: {normalized_url}")
            
        return normalized_url
    
    def create_dpop_proof(self, http_method: str, url: str, nonce: Optional[str] = None, access_token: Optional[str] = None) -> str:
        """
        Create a DPoP proof JWT for API requests with token binding.
        
        Args:
            http_method: HTTP method (POST, GET, etc.)
            url: Target URL
            nonce: Optional nonce from server
            access_token: Optional access token to bind to the proof
            
        Returns:
            DPoP proof JWT string
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.dpop_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Normalize URL for DPoP
        normalized_url = self._normalize_url_for_dpop(http_method, url)
        
        # Create DPoP proof JWT
        now = int(time.time())
        proof = {
            "jti": str(uuid.uuid4()),
            "htm": http_method,
            "htu": normalized_url,
            "iat": now,
            "exp": now + 60,  # Valid for 1 minute
        }
        
        # Add token binding with 'ath' claim if access_token is provided
        if access_token:
            # Create hash of the access token for the 'ath' claim
            access_token_hash = hashlib.sha256(access_token.encode()).digest()
            # Base64url encode the hash
            ath = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')
            proof["ath"] = ath
            logger.debug(f"Generated access token hash (ath) for token binding: {ath[:10]}...")
        
        # Include server-provided nonce when present to meet DPoP requirements
        if nonce:
            proof["nonce"] = nonce
            logger.debug(f"Including nonce in DPoP proof: {nonce}")
        
        # Create the header with the JWK
        header = {
            "typ": "dpop+jwt",
            "alg": "RS256",
            "jwk": self.dpop_jwk
        }
        
        # Sign the JWT
        dpop_proof = jwt.encode(
            payload=proof,
            key=private_key_pem,
            algorithm="RS256",
            headers=header
        )
        
        # Decode payload at debug level to validate proof structure
        try:
            decoded = jwt.decode(dpop_proof, options={"verify_signature": False})
            logger.debug(f"DPoP proof payload: {json.dumps(decoded)}")
        except Exception as e:
            logger.error(f"Error decoding JWT: {e}")
        
        return dpop_proof
    
    def get_dpop_nonce(self, url: str) -> Optional[str]:
        """
        Get a DPoP nonce from the server by making a minimal request.
        
        Args:
            url: The URL to request the nonce from
            
        Returns:
            The DPoP nonce if available, None otherwise
        """
        try:
            # Create initial DPoP proof without nonce
            initial_proof = self.create_dpop_proof("POST", url)
            
            minimal_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            # Make a minimal request to get the nonce
            minimal_response = self.session.post(
                url,
                headers=minimal_headers,
                data={"client_id": self.client_id},
                timeout=10
            )
            
            logger.debug(f"Minimal POST status: {minimal_response.status_code}")
            logger.debug(f"Response headers: {dict(minimal_response.headers)}")
            
            # Check for DPoP-Nonce header
            if "DPoP-Nonce" in minimal_response.headers:
                dpop_nonce = minimal_response.headers.get("DPoP-Nonce")
                logger.info(f"Got DPoP nonce from response: {dpop_nonce}")
                return dpop_nonce
            
            return None
                
        except Exception as e:
            logger.error(f"Error getting DPoP nonce: {str(e)}")
            return None
    
    def generate_pkce_pair(self) -> tuple:
        """
        Generate PKCE code verifier and challenge.
        
        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate a random code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        # Remove padding
        code_verifier = code_verifier.rstrip('=')
        
        # Create the code challenge (S256 method - SHA256 hash of verifier)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8')
        # Remove padding
        code_challenge = code_challenge.rstrip('=')
        
        logger.debug(f"Generated PKCE pair - Verifier length: {len(code_verifier)}, Challenge length: {len(code_challenge)}")
        return code_verifier, code_challenge

    def get_authorization_url(self, state: str, code_challenge: str) -> str:
        """
        Generate the authorization URL for the Okta OAuth flow with PKCE.
        
        Args:
            state: A random string for CSRF protection
            code_challenge: The PKCE code challenge
            
        Returns:
            The complete authorization URL to redirect the user to
        """
        # Build the authorization URL with required parameters including PKCE
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'state': state,
            'scope': 'openid profile email',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        # Convert params to query string
        query_string = '&'.join([f"{key}={requests.utils.quote(value)}" for key, value in params.items()])
        
        # Build the complete authorization URL
        auth_url = f"{self.authorization_endpoint}?{query_string}"
        
        logger.debug(f"Generated authorization URL with PKCE: {auth_url[:50]}...")
        return auth_url

    def exchange_code_for_tokens(self, code: str, code_verifier: str) -> Dict:
        """
        Exchange the authorization code for access/refresh tokens using PKCE.
        
        Args:
            code: The authorization code received from the authorization server
            code_verifier: The PKCE code verifier generated during authorization
            
        Returns:
            Dict containing the access token, id_token, refresh_token and other information
            
        Raises:
            Exception: If the token request fails
        """
        try:
            logger.info("Exchanging authorization code for tokens")
            
            # Step 1: Request a DPoP nonce before submitting token request
            dpop_nonce = self.get_dpop_nonce(self.token_endpoint)
            
            # Step 2: Build DPoP proof including nonce when available
            dpop_proof = self.create_dpop_proof("POST", self.token_endpoint, dpop_nonce)
            
            # Prepare the token request data with PKCE
            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.redirect_uri,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'code_verifier': code_verifier,  # PKCE code verifier
                'token_type': 'DPoP'  # Request DPoP token
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpop_proof  # Add DPoP proof
            }
            
            # Log request metadata at debug level for traceability
            logger.debug(f"Token exchange details - Client ID: {self.client_id}, Endpoint: {self.token_endpoint}")
            logger.debug(f"Redirect URI: {self.redirect_uri}")
            
            # Make the token request
            logger.debug(f"Making token request to {self.token_endpoint}")
            token_response = self.session.post(
                self.token_endpoint,
                headers=headers,
                data=token_data,
                timeout=15
            )
            
            logger.debug(f"Token exchange response status: {token_response.status_code}")
            logger.debug(f"Token exchange response headers: {dict(token_response.headers)}")
            
            # Check if we need to retry with a new nonce
            if token_response.status_code in [400, 401] and "DPoP-Nonce" in token_response.headers:
                logger.info("Got a new nonce in the error response, retrying...")
                new_nonce = token_response.headers.get("DPoP-Nonce")
                logger.debug(f"New nonce: {new_nonce}")
                
                # Create a new proof with the new nonce
                new_proof = self.create_dpop_proof("POST", self.token_endpoint, new_nonce)
                headers["DPoP"] = new_proof
                
                # Try again
                logger.info("Retrying with new nonce...")
                token_response = self.session.post(
                    self.token_endpoint,
                    headers=headers,
                    data=token_data,
                    timeout=15
                )
                
                logger.debug(f"Retry status code: {token_response.status_code}")
            
            # Check if the request was successful
            if token_response.status_code == 200:
                # Parse the token response
                token_data = token_response.json()
                logger.info("Successfully exchanged code for tokens")
                
                # Log token information (but not the full tokens)
                access_token = token_data.get('access_token', '')
                id_token = token_data.get('id_token', '')
                refresh_token = token_data.get('refresh_token', '')
                
                logger.debug(f"Received access token (length: {len(access_token)})")
                if id_token:
                    logger.debug(f"Received ID token (length: {len(id_token)})")
                if refresh_token:
                    logger.debug(f"Received refresh token (length: {len(refresh_token)})")
                
                return token_data
            else:
                # Handle error response
                error_text = token_response.text[:500]
                logger.debug(f"Error response text: {error_text}")
                
                # Extract error details from JSON if possible
                error_msg = f"Status code: {token_response.status_code}"
                try:
                    error_json = token_response.json()
                    error = error_json.get('error')
                    error_description = error_json.get('error_description')
                    
                    if error and error_description:
                        error_msg = f"{error}: {error_description}"
                    elif error:
                        error_msg = f"{error}"
                    elif error_description:
                        error_msg = f"{error_description}"
                    else:
                        # If no structured error info is available, use the raw text
                        error_msg = error_text if error_text else f"HTTP {token_response.status_code}"
                except Exception as json_error:
                    logger.warning(f"Could not parse error response as JSON: {json_error}")
                    # Use the raw response text as the error message
                    error_msg = error_text if error_text else f"HTTP {token_response.status_code}"
                
                logger.error(f"Token exchange failed: {error_msg}")
                raise Exception(f"Failed to exchange code for tokens: {error_msg}")
        
        except requests.exceptions.RequestException as req_ex:
            # Handle network/request errors specifically
            logger.error(f"Network error during token exchange: {str(req_ex)}")
            raise Exception(f"Network error during token exchange: {str(req_ex)}")
        except Exception as e:
            logger.error(f"Error exchanging code for tokens: {str(e)}")
            raise Exception(f"Code exchange failed: {str(e)}")
    
    def get_user_info(self, access_token: str, token_type: str = "Bearer", id_token: Optional[str] = None) -> Dict:
        """
        Get user information from Okta userinfo endpoint using the access token
        
        Args:
            access_token: The OAuth access token
            token_type: The token type (Bearer)
            id_token: Optional ID token for fallback extraction
            
        Returns:
            Dict containing user information
            
        Raises:
            Exception: If the user info request fails
        """
        try:
            logger.info("Getting user info from Okta")
            
            headers = {
                "Authorization": f"{token_type} {access_token}",
                "Accept": "application/json"
            }
            
            # Make the userinfo request
            userinfo_response = self.session.get(
                self.userinfo_endpoint,
                headers=headers,
                timeout=15
            )
            
            logger.debug(f"User info response status: {userinfo_response.status_code}")
            
            # Check if the request was successful
            if userinfo_response.status_code == 200:
                userinfo_data = userinfo_response.json()
                logger.info(f"Successfully retrieved user info for subject: {userinfo_data.get('sub', 'unknown')}")
                return userinfo_data
            else:
                # If we have an ID token, try to extract user info from it as fallback
                if id_token:
                    logger.warning("User info request failed, trying to extract from ID token")
                    return self._parse_id_token(id_token)
                    
                # Handle error response
                error_text = userinfo_response.text[:200]
                try:
                    error_json = userinfo_response.json()
                    error_msg = error_json.get('error_description') or error_json.get('error') or error_text
                except:
                    error_msg = error_text
                
                logger.error(f"User info request failed: {error_msg}")
                raise Exception(f"Failed to get user info: {error_msg}")
        
        except Exception as e:
            if id_token:
                logger.warning(f"User info request failed: {str(e)}, trying ID token")
                return self._parse_id_token(id_token)
            else:
                logger.error(f"Error getting user info: {str(e)}")
                raise Exception(f"User info request failed: {str(e)}")
    
    def _parse_id_token(self, id_token: str) -> Dict:
        """
        Parse and validate the ID token to extract user information
        
        Args:
            id_token: The ID token string
            
        Returns:
            Dict containing user claims from the ID token
            
        Raises:
            Exception: If parsing fails
        """
        try:
            # Decode the token without verification (we're just extracting claims)
            # In a production environment, you should verify the signature
            decoded = jwt.decode(
                id_token,
                options={"verify_signature": False}
            )
            
            logger.info(f"Successfully extracted user info from ID token for subject: {decoded.get('sub', 'unknown')}")
            return decoded
            
        except Exception as e:
            logger.error(f"Error parsing ID token: {str(e)}")
            raise Exception(f"Failed to parse ID token: {str(e)}")
            
    def refresh_access_token(self, refresh_token: str) -> Dict:
        """
        Refresh the access token using a refresh token
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Dict containing the new tokens
            
        Raises:
            Exception: If the token refresh fails
        """
        try:
            logger.info("Refreshing access token")
            
            # Get a DPoP nonce
            dpop_nonce = self.get_dpop_nonce(self.token_endpoint)
            
            # Create DPoP proof with the nonce
            dpop_proof = self.create_dpop_proof("POST", self.token_endpoint, dpop_nonce)
            
            # Prepare the token refresh request
            refresh_data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'token_type': 'DPoP'  # Request DPoP token
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
                'DPoP': dpop_proof
            }
            
            # Make the refresh token request
            refresh_response = self.session.post(
                self.token_endpoint,
                headers=headers,
                data=refresh_data,
                timeout=15
            )
            
            logger.debug(f"Token refresh response status: {refresh_response.status_code}")
            
            # Check if we need to retry with a new nonce
            if refresh_response.status_code in [400, 401] and "DPoP-Nonce" in refresh_response.headers:
                logger.info("Got a new nonce in the error response, retrying refresh...")
                new_nonce = refresh_response.headers.get("DPoP-Nonce")
                
                # Create a new proof with the new nonce
                new_proof = self.create_dpop_proof("POST", self.token_endpoint, new_nonce)
                headers["DPoP"] = new_proof
                
                # Try again
                refresh_response = self.session.post(
                    self.token_endpoint,
                    headers=headers,
                    data=refresh_data,
                    timeout=15
                )
            
            # Check if the request was successful
            if refresh_response.status_code == 200:
                token_data = refresh_response.json()
                logger.info("Successfully refreshed access token")
                
                # Log token information (but not the full tokens)
                access_token = token_data.get('access_token', '')
                id_token = token_data.get('id_token', '')
                new_refresh_token = token_data.get('refresh_token', '')
                
                logger.debug(f"Received new access token (length: {len(access_token)})")
                if id_token:
                    logger.debug(f"Received new ID token (length: {len(id_token)})")
                if new_refresh_token:
                    logger.debug("Received new refresh token (refresh token rotation)")
                
                return token_data
            else:
                # Handle error response
                error_text = refresh_response.text[:200]
                try:
                    error_json = refresh_response.json()
                    error_msg = f"{error_json.get('error')}: {error_json.get('error_description')}"
                except:
                    error_msg = error_text
                
                logger.error(f"Token refresh failed: {error_msg}")
                raise Exception(f"Failed to refresh token: {error_msg}")
        
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            raise Exception(f"Token refresh failed: {str(e)}")

    def introspect_token(self, token: str, token_type_hint: str = "access_token") -> Dict[str, Any]:
        """
        Introspect a token to verify its validity and get information about it
        
        Args:
            token: The token to introspect
            token_type_hint: The type of token ('access_token' or 'refresh_token')
            
        Returns:
            Dict containing token information including if it's active
        """
        try:
            logger.debug(f"Introspecting {token_type_hint}")
            
            # Prepare the introspection request
            introspect_data = {
                'token': token,
                'token_type_hint': token_type_hint,
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Make the introspection request
            introspect_response = self.session.post(
                self.introspect_endpoint,
                headers=headers,
                data=introspect_data,
                timeout=15
            )
            
            if introspect_response.status_code == 200:
                introspect_data = introspect_response.json()
                is_active = introspect_data.get('active', False)
                
                if is_active:
                    logger.debug(f"Token is active, expires at: {introspect_data.get('exp', 'unknown')}")
                else:
                    logger.debug("Token is not active")
                    
                return introspect_data
            else:
                logger.warning(f"Token introspection failed: {introspect_response.status_code}")
                return {"active": False, "error": f"HTTP {introspect_response.status_code}"}
                
        except Exception as e:
            logger.error(f"Error during token introspection: {str(e)}")
            return {"active": False, "error": str(e)}