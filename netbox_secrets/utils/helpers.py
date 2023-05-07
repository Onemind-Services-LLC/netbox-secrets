import base64

from ..constants import SESSION_COOKIE_NAME

__all__ = ['get_session_key']


def get_session_key(request):
    """
    Extract and decode the session key sent with a request. Returns None if no session key was provided.
    """
    session_key = request.COOKIES.get(SESSION_COOKIE_NAME, None)
    if session_key is not None:
        return base64.b64decode(session_key)
    return session_key
