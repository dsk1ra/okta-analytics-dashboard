import logging
import requests
import base64
import time
import uuid
import jwt
import json
import hashlib
import os
import re
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional, Tuple, Any
from django.conf import settings
from django.core.cache import cache
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class OktaOAuthClient:
    """
    OAuth client for Okta authentication with enhanced security features.
    
    This class implements OAuth 2.0 flows to authenticate with Okta,
    supporting the zero trust security model through:
    1. DPoP (Demonstrating Proof of Possession) for token binding
    2. private_key_jwt for client authentication (more secure than client secret)
    3. Automatic token refresh and proper token lifetime management
    """
    
    def __init__(self, use_registered_keys=True):
        """
        Initialize the OAuth client with settings from Django configuration
        
        Args:
            use_registered_keys: Whether to use the registered keys from the keys/ directory
                                 If False, dynamically generate keys (but this won't work with real Okta unless registered)
        """
        # Store API/Log credentials for accessing Okta APIs
        self.client_id = settings.OKTA_CLIENT_ID
        self.client_secret = settings.OKTA_CLIENT_SECRET
        self.org_url = settings.OKTA_ORG_URL
        
        # Store authorization credentials for user authentication flows
        self.authorization_client_id = settings.OKTA_AUTHORIZATION_CLIENT_ID
        self.authorization_client_secret = settings.OKTA_AUTHORIZATION_CLIENT_SECRET
        self.authorization_org_url = settings.OKTA_AUTHORIZATION_ORG_URL
        
        # Store common settings
        self.redirect_uri = settings.OKTA_REDIRECT_URI
        
        # Store authentication endpoints (user login)
        self.authorization_endpoint = settings.OKTA_AUTHORIZATION_ENDPOINT
        self.token_endpoint = settings.OKTA_TOKEN_ENDPOINT
        self.userinfo_endpoint = settings.OKTA_USER_INFO_ENDPOINT
        
        # Store API endpoints (log retrieval)
        self.api_token_endpoint = settings.OKTA_API_TOKEN_ENDPOINT
        self.api_logs_endpoint = settings.OKTA_API_LOGS_ENDPOINT
        self.api_users_endpoint = settings.OKTA_API_USERS_ENDPOINT
        
        # Log important configuration details
        logger.info(f"OktaOAuthClient initialized with auth org: {self.authorization_org_url}")
        logger.info(f"API org: {self.org_url}")
        
        # Load or generate RSA key pair for DPoP
        self._setup_key_pair(use_registered_keys)
        
        # Session for connection pooling and performance optimization
        self.session = self._create_optimized_session()
    
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
    
    def _setup_key_pair(self, use_registered_keys=True):
        """
        Set up RSA key pairs for both DPoP and client authentication
        
        Args:
            use_registered_keys: Whether to use the registered keys from keys/ directory
        """
        if use_registered_keys:
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
                
                # Get public key in JWK format from the loaded key
                public_key = self.private_key.public_key()
                public_numbers = public_key.public_numbers()
                
                # Create a deterministic key ID so uploads are consistent
                kid_source = f"{public_numbers.n}:{public_numbers.e}".encode()
                kid_hash = hashlib.sha256(kid_source).digest()
                kid_b64 = base64.urlsafe_b64encode(kid_hash).decode().rstrip('=')

                # Convert to JWK format
                self.jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "kid": kid_b64[:16],
                    "use": "sig"
                }
                
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

                # Persist the generated private key so it stays stable across restarts
                try:
                    keys_dir = os.path.join(settings.BASE_DIR, 'keys')
                    os.makedirs(keys_dir, exist_ok=True)
                    private_key_path = os.path.join(keys_dir, 'private_key.pem')
                    private_key_pem = self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    with open(private_key_path, 'wb') as f:
                        f.write(private_key_pem)
                    logger.info(f"Saved new private key to {private_key_path}")
                except Exception as save_err:
                    logger.error(f"Failed to persist generated private key: {save_err}")
                
                # Get public key in JWK format
                public_key = self.private_key.public_key()
                public_numbers = public_key.public_numbers()
                
                # Create a deterministic key ID so uploads are consistent
                kid_source = f"{public_numbers.n}:{public_numbers.e}".encode()
                kid_hash = hashlib.sha256(kid_source).digest()
                kid_b64 = base64.urlsafe_b64encode(kid_hash).decode().rstrip('=')

                # Convert to JWK format
                self.jwk = {
                    "kty": "RSA",
                    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                    "alg": "RS256",
                    "kid": kid_b64[:16],
                    "use": "sig"
                }
                
                # Use the same key for DPoP in this case
                self.dpop_private_key = self.private_key
                self.dpop_jwk = self.jwk
    
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
        
        # For Okta System Log API, use exactly '/api/v1/logs' as specified in documentation
        if '/api/v1/logs' in url:
            normalized_url = url
            logger.debug(f"Using documented API path for logs API: {normalized_url}")
        elif 'oauth2/v1/token' in url:
            # For token endpoint, use full URL (this works)
            normalized_url = url
            logger.debug(f"Using full URL for token endpoint: {normalized_url}")
        else:
            # For other cases, use the full URL
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
        
        # Add nonce if provided - THIS IS CRITICAL
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
        
        # Debug: decode and print the payload to verify
        try:
            decoded = jwt.decode(dpop_proof, options={"verify_signature": False})
            logger.debug(f"DPoP proof payload: {json.dumps(decoded)}")
        except Exception as e:
            logger.error(f"Error decoding JWT: {e}")
        
        return dpop_proof
    
    def create_client_assertion(self, audience: str) -> str:
        """
        Create a signed JWT assertion for client authentication using private_key_jwt
        
        Args:
            audience: The audience for the token (typically the token endpoint)
            
        Returns:
            Signed JWT token as string
        """
        # Create the private key in PEM format for JWT signing
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create JWT assertion
        now = int(time.time())
        payload = {
            "iss": self.client_id,      # Issuer - must be the client_id
            "sub": self.client_id,      # Subject - must be the client_id
            "aud": audience,            # Audience - token endpoint
            "jti": str(uuid.uuid4()),   # Unique identifier
            "iat": now,                 # Issued at time
            "exp": now + 60             # Expiration time (1 minute)
        }
        
        # Sign the JWT and include kid so Okta can match the uploaded public key
        client_assertion = jwt.encode(
            payload=payload,
            key=private_key_pem,
            algorithm="RS256",
            headers={"kid": self.jwk.get("kid")}
        )
        
        logger.debug("Created private_key_jwt client assertion for authentication")
        return client_assertion
    
    def get_dpop_nonce(self, url: str) -> Optional[str]:
        """
        Get a DPoP nonce from the server by making a minimal request.
        This is required for DPoP security to prevent replay attacks.
        
        Args:
            url: The URL to request the nonce from
            
        Returns:
            The DPoP nonce if available, None otherwise
        """
        try:
            # Create initial DPoP proof without nonce
            initial_proof = self.create_dpop_proof("POST", url)
            
            # Create client assertion for private_key_jwt
            client_assertion = self.create_client_assertion(url)
            
            minimal_headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "DPoP": initial_proof
            }
            
            minimal_data = {
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "grant_type": "client_credentials"
            }
            
            dpop_nonce = None
            
            # Make a minimal request to get the nonce
            minimal_response = self.session.post(
                url,
                headers=minimal_headers,
                data=minimal_data,
                timeout=10
            )
            
            logger.debug(f"Minimal POST status: {minimal_response.status_code}")
            logger.debug(f"Response headers: {dict(minimal_response.headers)}")
            
            # Check for DPoP-Nonce header
            if "DPoP-Nonce" in minimal_response.headers:
                dpop_nonce = minimal_response.headers.get("DPoP-Nonce")
                logger.info(f"Got DPoP nonce from response: {dpop_nonce}")
                return dpop_nonce
            
            # Try to extract nonce from error response
            try:
                error_data = minimal_response.json()
                logger.debug(f"Error response: {error_data}")
                
                # Check error description for nonce info
                error_desc = error_data.get("error_description", "")
                if "nonce" in error_desc.lower():
                    logger.info("Error indicates nonce issue")
                    
                    # Check WWW-Authenticate header
                    www_auth = minimal_response.headers.get("WWW-Authenticate", "")
                    if "nonce=" in www_auth:
                        nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                        if nonce_match:
                            dpop_nonce = nonce_match.group(1)
                            logger.info(f"Extracted nonce from WWW-Authenticate: {dpop_nonce}")
                            return dpop_nonce
            except Exception as parse_error:
                logger.error(f"Error parsing response: {parse_error}")
                logger.debug(f"Raw response: {minimal_response.text[:200]}")
            
            # As a last resort, try to get the nonce with a separate HEAD request
            try:
                head_response = self.session.head(
                    url,
                    headers={"Accept": "application/json", "DPoP": initial_proof},
                    timeout=5
                )
                
                for header_name, header_value in head_response.headers.items():
                    if header_name.lower() == 'dpop-nonce':
                        logger.debug(f"Got DPoP nonce from HEAD request: {header_value}")
                        return header_value
                
                www_auth = head_response.headers.get("WWW-Authenticate", "")
                if "nonce=" in www_auth:
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        nonce = nonce_match.group(1)
                        logger.debug(f"Extracted nonce from HEAD WWW-Authenticate: {nonce}")
                        return nonce
            except Exception as head_error:
                logger.warning(f"Error in HEAD request for nonce: {head_error}")
            
            return None
                
        except Exception as e:
            logger.error(f"Error getting DPoP nonce: {str(e)}")
            return None
    
    def get_client_credentials_token(self, scopes: str = "okta.logs.read okta.users.read") -> Dict:
        """
        Get an OAuth 2.0 access token using client credentials flow with DPoP support.
        Primary: private_key_jwt (required by Org Authorization Server)
        Fallback: client_secret (if server policy allows it)
        """
        token_url = self.api_token_endpoint
        logger.info(f"Attempting OAuth token request at {token_url}")

        pk_err = None

        # 1) Try private_key_jwt first (required by server policy)
        try:
            return self._get_client_credentials_token_with_private_key_jwt(token_url, scopes)
        except Exception as err:
            pk_err = err
            logger.warning(f"private_key_jwt attempt failed: {pk_err}")

        # 2) Fallback to client_secret (only if server allows)
        try:
            logger.info("Falling back to client_secret auth")
            return self._get_client_credentials_token_with_secret(
                token_url,
                scopes,
                client_id=self.client_id,
                client_secret=self.client_secret,
                use_dpop=True
            )
        except Exception as secret_err:
            logger.error(f"client_secret attempt failed: {secret_err}")
            raise Exception(f"Failed to obtain OAuth token: pk_jwt error: {pk_err} | client_secret error: {secret_err}")
    
    def _get_client_credentials_token_with_secret(self, token_url: str, scopes: str, client_id: str = None, client_secret: str = None, use_dpop: bool = True) -> Dict:
        """
        Get client credentials token using client_secret with optional DPoP
        
        Args:
            token_url: Token endpoint URL
            scopes: Requested scopes
            client_id: Override client ID (defaults to self.client_id)
            client_secret: Override client secret (defaults to self.client_secret)
            use_dpop: Whether to use DPoP proof for the request
            
        Returns:
            Token response dict
        """
        # Use provided credentials or defaults
        use_client_id = client_id or self.client_id
        use_client_secret = client_secret or self.client_secret
        
        try:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            
            data = {
                "client_id": use_client_id,
                "client_secret": use_client_secret,
                "grant_type": "client_credentials",
                "scope": scopes
            }
            
            logger.debug(f"Requesting token from: {token_url}")
            logger.debug(f"Using client ID: {use_client_id}")
            logger.debug(f"Using scopes: {scopes}")
            logger.debug(f"Using DPoP: {use_dpop}")
            
            # Add DPoP header if required (first attempt without nonce)
            dpop_nonce = None
            if use_dpop:
                try:
                    dpop_proof = self.create_dpop_proof("POST", token_url, None)
                    headers["DPoP"] = dpop_proof
                    logger.debug(f"Added DPoP header to token request (no nonce)")
                except Exception as dpop_error:
                    logger.warning(f"Failed to create DPoP proof: {dpop_error}, continuing without DPoP")
                    use_dpop = False
            
            token_response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                timeout=15
            )
            
            logger.debug(f"Token request status code: {token_response.status_code}")
            logger.debug(f"Token response headers: {dict(token_response.headers)}")
            
            # Check for DPoP-Nonce in response
            if "DPoP-Nonce" in token_response.headers:
                dpop_nonce = token_response.headers.get("DPoP-Nonce")
                logger.debug(f"Received DPoP-Nonce from server: {dpop_nonce}")
            
            # If we get 400 with use_dpop_nonce error, retry with nonce
            if token_response.status_code == 400:
                error_json = token_response.json()
                if error_json.get('error') == 'use_dpop_nonce' and dpop_nonce:
                    logger.info(f"Retrying token request with DPoP nonce...")
                    
                    # Create new DPoP proof with nonce
                    dpop_proof_with_nonce = self.create_dpop_proof("POST", token_url, dpop_nonce)
                    headers["DPoP"] = dpop_proof_with_nonce
                    
                    # Retry the request
                    token_response = self.session.post(
                        token_url,
                        headers=headers,
                        data=data,
                        timeout=15
                    )
                    
                    logger.debug(f"Retry token request status code: {token_response.status_code}")
            
            if token_response.status_code == 200:
                logger.info("✓ Successfully obtained token!")
                token_json = token_response.json()
                access_token = token_json.get("access_token")
                expires_in = token_json.get("expires_in", 3600)
                token_type = token_json.get("token_type", "Bearer")
                
                logger.info(f"Token type: {token_type}")
                logger.info(f"Expires in: {expires_in} seconds")
                logger.debug(f"Access token: {access_token[:20] if access_token else 'None'}...")
                
                scope = token_json.get("scope", "")
                logger.info(f"Granted scopes: {scope}")
                
                # Store nonce if provided for future use
                if dpop_nonce:
                    token_json['_dpop_nonce'] = dpop_nonce
                
                return token_json
            else:
                error_text = token_response.text[:1000]
                logger.error(f"✗ Token request failed with status {token_response.status_code}")
                logger.error(f"Response body: {error_text}")
                
                # Try to parse the error response
                try:
                    error_json = token_response.json()
                    error = error_json.get('error', 'Unknown error')
                    error_desc = error_json.get('error_description', 'No description provided')
                    logger.error(f"Okta error: {error}")
                    logger.error(f"Error description: {error_desc}")
                    raise Exception(f"OAuth error: {error} - {error_desc}")
                except Exception as parse_error:
                    # If we can't parse JSON, just use the raw response
                    if isinstance(parse_error, Exception) and "OAuth error" in str(parse_error):
                        raise parse_error
                    raise Exception(f"Token request failed with status {token_response.status_code}: {error_text}")
                
        except Exception as e:
            logger.error(f"Error in token request: {str(e)}")
            raise Exception(f"OAuth token acquisition failed: {str(e)}")

    def _get_client_credentials_token_with_private_key_jwt(self, token_url: str, scopes: str) -> Dict:
        """
        Get client credentials token using private_key_jwt with DPoP and nonce retry.
        """
        try:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }

            client_assertion = self.create_client_assertion(token_url)
            data = {
                "grant_type": "client_credentials",
                "scope": scopes,
                "client_id": self.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion
            }

            logger.debug(f"Requesting token (pk_jwt) from: {token_url}")

            # First attempt without nonce
            dpop_nonce = None
            try:
                dpop_proof = self.create_dpop_proof("POST", token_url, None)
                headers["DPoP"] = dpop_proof
            except Exception as dpop_err:
                logger.warning(f"DPoP proof creation failed, continuing without DPoP: {dpop_err}")

            token_response = self.session.post(
                token_url,
                headers=headers,
                data=data,
                timeout=15
            )

            # Capture nonce if provided
            if "DPoP-Nonce" in token_response.headers:
                dpop_nonce = token_response.headers.get("DPoP-Nonce")
                logger.debug(f"Received DPoP-Nonce: {dpop_nonce}")

            # Retry with nonce if required
            if token_response.status_code == 400:
                try:
                    err_json = token_response.json()
                    if err_json.get("error") == "use_dpop_nonce" and dpop_nonce:
                        logger.info("Retrying pk_jwt token request with DPoP nonce")

                        # Regenerate assertion to avoid replay errors on retry
                        data["client_assertion"] = self.create_client_assertion(token_url)

                        dpop_proof = self.create_dpop_proof("POST", token_url, dpop_nonce)
                        headers["DPoP"] = dpop_proof
                        token_response = self.session.post(
                            token_url,
                            headers=headers,
                            data=data,
                            timeout=15
                        )

                    # If Okta says assertion already used, regenerate once and retry
                    if err_json.get("error_description", "").lower().find("already been used") != -1:
                        logger.info("Regenerating client_assertion after reuse error")
                        data["client_assertion"] = self.create_client_assertion(token_url)
                        dpop_proof = self.create_dpop_proof("POST", token_url, dpop_nonce)
                        headers["DPoP"] = dpop_proof
                        token_response = self.session.post(
                            token_url,
                            headers=headers,
                            data=data,
                            timeout=15
                        )
                except Exception:
                    pass

            if token_response.status_code == 200:
                token_json = token_response.json()
                if dpop_nonce:
                    token_json['_dpop_nonce'] = dpop_nonce
                logger.info("Successfully obtained token with private_key_jwt")
                return token_json

            # Failure path
            err_text = token_response.text[:500]
            try:
                err_json = token_response.json()
                err = err_json.get('error', 'Unknown error')
                err_desc = err_json.get('error_description', 'No description provided')
                raise Exception(f"OAuth error: {err} - {err_desc}")
            except Exception as parse_err:
                if "OAuth error" in str(parse_err):
                    raise
                raise Exception(f"Token request failed with status {token_response.status_code}: {err_text}")

        except Exception as e:
            logger.error(f"Error in pk_jwt token request: {e}")
            raise
    
    def create_api_headers(self, access_token: str, method: str = "GET", url: str = "", nonce: Optional[str] = None, use_dpop: bool = False) -> Dict[str, str]:
        """
        Create headers for Okta API requests with optional DPoP binding
        
        Args:
            access_token: The access token
            method: HTTP method for the request
            url: Target URL for the request
            nonce: Optional DPoP nonce
            use_dpop: Whether to use DPoP (for private key JWT only)
            
        Returns:
            Dict of HTTP headers
        """
        if use_dpop:
            # Create DPoP proof with token binding (only for private key JWT)
            dpop_proof = self.create_dpop_proof(method, url, nonce, access_token)
            
            # Create headers with DPoP
            headers = {
                "Authorization": f"DPoP {access_token}",
                "Accept": "application/json",
                "DPoP": dpop_proof
            }
        else:
            # Simple Bearer token (for client_secret method)
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        
        return headers

    def get_authorization_url(self, state: str) -> str:
        """
        Generate the authorization URL for the Okta OAuth flow.
        
        Args:
            state: A random string for CSRF protection
            
        Returns:
            The complete authorization URL to redirect the user to
        """
        # Build the authorization URL with required parameters
        params = {
            'client_id': self.authorization_client_id,  # Use authorization client ID
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'state': state,
            'scope': 'openid profile email'
        }
        
        # Convert params to query string
        query_string = '&'.join([f"{key}={requests.utils.quote(value)}" for key, value in params.items()])
        
        # Use the authorization org URL directly instead of the endpoint
        auth_endpoint = f"{self.authorization_org_url}/oauth2/v1/authorize"
        auth_url = f"{auth_endpoint}?{query_string}"
        
        logger.debug(f"Generated authorization URL: {auth_url[:50]}...")
        return auth_url

    def exchange_code_for_tokens(self, code: str) -> Dict:
        """
        Exchange the authorization code for access/refresh tokens
        
        Args:
            code: The authorization code received from the authorization server
            
        Returns:
            Dict containing the access token, id_token, refresh_token and other information
            
        Raises:
            Exception: If the token request fails
        """
        try:
            logger.info("Exchanging authorization code for tokens")
            
            # Prepare the token request data - explicitly use authorization organization credentials
            token_data = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.redirect_uri,
                'client_id': self.authorization_client_id,  # Explicitly use the authorization client ID
                'client_secret': self.authorization_client_secret  # Explicitly use the authorization client secret
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Log important details for debugging
            logger.debug(f"Token exchange details - Client ID: {self.authorization_client_id}, Endpoint: {self.token_endpoint}")
            logger.debug(f"Authorization org URL: {self.authorization_org_url}")
            logger.debug(f"Redirect URI: {self.redirect_uri}")
            
            # Make the token request to the authorization org URL token endpoint
            token_endpoint = f"{self.authorization_org_url}/oauth2/v1/token"
            logger.debug(f"Making token request to {token_endpoint}")
            token_response = self.session.post(
                token_endpoint,
                headers=headers,
                data=token_data,
                timeout=15
            )
            
            logger.debug(f"Token exchange response status: {token_response.status_code}")
            logger.debug(f"Token exchange response headers: {dict(token_response.headers)}")
            
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
            token_type: The token type (Bearer or DPoP)
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
            
            # Prepare the token refresh request
            refresh_data = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': self.authorization_client_id,
                'client_secret': self.authorization_client_secret
            }
            
            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            # Make the refresh token request
            refresh_response = self.session.post(
                self.token_endpoint,
                headers=headers,
                data=refresh_data,
                timeout=15
            )
            
            logger.debug(f"Token refresh response status: {refresh_response.status_code}")
            
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