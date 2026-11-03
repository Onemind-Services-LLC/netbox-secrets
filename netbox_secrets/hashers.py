import hashlib
import hmac
import warnings

from django.contrib.auth.hashers import PBKDF2PasswordHasher, check_password

__all__ = [
    'SecretValidationHasher',
    'make_session_key_hash',
    'check_session_key_hash',
    'make_secret_hash',
    'check_secret_hash',
]

SESSION_KEY_HASH_PREFIX = 'sha256$'
SECRET_HASH_PREFIX = 'hmac_sha256$'


# TODO: Remove the legacy (PBKDF2) secret hash support in NetBox v4.8: ``SecretValidationHasher`` and the legacy branch
#  of ``check_secret_hash``.
LEGACY_HASH_WARNING = (
    "Legacy (PBKDF2) secret hashes are deprecated and support for them will be removed in NetBox v4.8."
)


class SecretValidationHasher(PBKDF2PasswordHasher):
    """
    We're using Django's stock SHA256 hasher with a low iteration count to avoid introducing excessive delay when
    retrieving a large number of Secrets (the plaintext of each Secret is validated against its hash upon decryption).

    Kept for backward compatibility: hashes created by older releases are still verified (see
    ``check_secret_hash``), new hashes use ``make_secret_hash``.

    Deprecated: this class (and legacy secret hash support) will be removed in NetBox v4.8.
    """

    iterations = 1000


def make_session_key_hash(session_key: bytes) -> str:
    """
    Hash a session key for later validation.

    A session key is 256 bits of random data, so it cannot be guessed or brute forced. A deliberately slow password
    hasher (PBKDF2) adds nothing here but costs CPU on every authenticated request, so a plain SHA-256 is used.
    """
    return SESSION_KEY_HASH_PREFIX + hashlib.sha256(session_key).hexdigest()


def check_session_key_hash(session_key: bytes, encoded: str) -> bool:
    """
    Verify a session key against a stored hash.

    Session keys created by older releases (PBKDF2 hash) are no longer supported, they have to be deleted and created
    again.
    """
    if not encoded.startswith(SESSION_KEY_HASH_PREFIX):
        return False

    return hmac.compare_digest(make_session_key_hash(session_key), encoded)


def make_secret_hash(plaintext: str, secret_key: bytes) -> str:
    """
    Create the validation hash stored next to a secret's ciphertext.

    It is an HMAC-SHA256 of the plaintext keyed with the master key. It is only a "did we decrypt with the right
    key" check, so it can be cheap, and because it is keyed an attacker who only has the database cannot use it to
    guess low-entropy plaintexts offline (an unkeyed fast hash would allow that).
    """
    digest = hmac.new(secret_key, plaintext.encode('utf-8'), hashlib.sha256).hexdigest()
    return SECRET_HASH_PREFIX + digest


def check_secret_hash(plaintext: str, secret_key: bytes, encoded: str) -> bool:
    """
    Verify decrypted plaintext against a stored secret hash.

    Hashes created by older releases (PBKDF2) are still accepted, but they are deprecated. Unlike session keys,
    secrets cannot simply be recreated by users.
    """
    if encoded.startswith(SECRET_HASH_PREFIX):
        return hmac.compare_digest(make_secret_hash(plaintext, secret_key), encoded)

    # TODO: Remove in NetBox v4.8 (legacy secret hash support)
    warnings.warn(LEGACY_HASH_WARNING, DeprecationWarning, stacklevel=2)
    return check_password(plaintext, encoded)
