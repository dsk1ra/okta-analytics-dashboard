import logging
import json
import os
from django.core.management.base import BaseCommand
from django.conf import settings
from core.services.okta_oauth import OktaOAuthClient

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Export the public JWK for registration with Okta'

    def handle(self, *args, **options):
        """Export the public key in JWK format"""
        try:
            # Initialize OAuth client to get the public key
            oauth_client = OktaOAuthClient()
            
            # Get the JWK (public key in JWK format)
            jwk = oauth_client.jwk
            
            self.stdout.write(self.style.SUCCESS("✓ Public Key (JWK Format):"))
            self.stdout.write("=" * 80)
            self.stdout.write(json.dumps(jwk, indent=2))
            self.stdout.write("=" * 80)
            
            # Save to file for easier copying
            export_path = os.path.join(settings.BASE_DIR, 'keys', 'public_key.json')
            os.makedirs(os.path.dirname(export_path), exist_ok=True)
            
            with open(export_path, 'w') as f:
                json.dump(jwk, f, indent=2)
            
            self.stdout.write(self.style.SUCCESS(f"\n✓ Public key saved to: {export_path}"))
            
            self.stdout.write(self.style.WARNING("\nInstructions for Okta Registration:"))
            self.stdout.write("1. Go to your Okta admin console")
            self.stdout.write(f"2. Navigate to: Applications > Applications > {settings.OKTA_CLIENT_ID}")
            self.stdout.write("3. Go to the 'Sign On' tab")
            self.stdout.write("4. Find the section 'Client Credentials' or 'Keys & Credentials'")
            self.stdout.write("5. Add the above JWK to the public keys section")
            self.stdout.write("6. Make sure 'private_key_jwt' is selected as the token authentication method")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"✗ Error exporting public key: {str(e)}"))
            logger.error(f"Error: {str(e)}", exc_info=True)
