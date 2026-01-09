"""
Token encryption service for securely handling OAuth tokens.
"""
import base64
import logging
from typing import Optional
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class TokenEncryptor:
    """
    Handles secure encryption and decryption of OAuth tokens.
    
    This class isolates the security-sensitive token encryption logic
    from the views, following the service layer pattern.
    """
    
    @staticmethod
    def _derive_key(user_id: str) -> bytes:
        """
        Derives an encryption key based on server secret and user ID
        
        Args:
            user_id: The user ID to incorporate into the key
            
        Returns:
            Derived encryption key as bytes
        """
        # Mix Django secret key with user-specific data for user isolation
        # This prevents one user's token from working if stolen and used with another user ID
        salt = settings.SECRET_KEY[:16].encode()
        user_specific = f"{user_id}-{settings.SECRET_KEY[16:32]}".encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        return base64.urlsafe_b64encode(kdf.derive(user_specific))
    
    @staticmethod
    def encrypt_token(token: str, user_id: str) -> str:
        """
        Encrypts a token for a specific user
        
        Args:
            token: The token to encrypt
            user_id: User ID to associate with the token
            
        Returns:
            Encrypted token as a string
        """
        key = TokenEncryptor._derive_key(user_id)
        f = Fernet(key)
        return f.encrypt(token.encode()).decode()
    
    @staticmethod
    def decrypt_token(encrypted_token: str, user_id: str) -> str:
        """
        Decrypts a token for a specific user
        
        Args:
            encrypted_token: The encrypted token string
            user_id: User ID associated with the token
            
        Returns:
            Original decrypted token as a string
            
        Raises:
            ValueError: If decryption fails
        """
        key = TokenEncryptor._derive_key(user_id)
        f = Fernet(key)
        try:
            return f.decrypt(encrypted_token.encode()).decode()
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            raise ValueError("Invalid or corrupted token")