def nonce_processor(request):
    """
    Context processor to add nonce to all template contexts.
    Used for Content Security Policy (CSP) compliance.
    """
    if hasattr(request, 'nonce'):
        return {'nonce': request.nonce}
    return {'nonce': ''}