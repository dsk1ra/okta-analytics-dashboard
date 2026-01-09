from rest_framework.versioning import URLPathVersioning
from rest_framework.settings import api_settings


class OktaDashboardVersioning(URLPathVersioning):
    """
    Custom versioning class for the Okta Dashboard API.
    
    This class handles API versioning using URL path segments,
    ensuring that API endpoints can evolve without breaking
    backwards compatibility.
    """
    default_version = 'v1'
    allowed_versions = ['v1', 'v2']
    version_param = 'version'
    
    def determine_version(self, request, *args, **kwargs):
        """
        Determine the appropriate version to use for the request.
        
        Args:
            request: The request object
            
        Returns:
            String representing API version
        """
        # First check if version is in the URL path
        version = super().determine_version(request, *args, **kwargs)
        
        # If not found in URL path but request has an explicit version header,
        # use that instead (with precedence over URL)
        version_header = request.META.get('HTTP_ACCEPT_VERSION')
        if version_header:
            version_header = version_header.lower()
            if version_header in self.allowed_versions:
                return version_header
        
        return version