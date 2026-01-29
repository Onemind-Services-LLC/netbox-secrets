import base64

from ..constants import SESSION_COOKIE_NAME

__all__ = ['get_session_key']


def get_session_key(request):
    """
    Extract and decode the session key sent with a request. Returns None if no session key was provided.
    """
    session_key = request.COOKIES.get(SESSION_COOKIE_NAME)
    if not session_key:
        session_key = request.META.get('HTTP_X_SESSION_KEY')
    if not session_key and hasattr(request, 'POST'):
        session_key = request.POST.get('session_key')

    if session_key is None:
        return None

    try:
        return base64.b64decode(session_key)
    except Exception:
        return None
