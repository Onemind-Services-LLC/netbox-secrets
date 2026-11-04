import warnings

from django.contrib.auth.hashers import make_password
from django.test import SimpleTestCase

from netbox_secrets.hashers import (
    SecretValidationHasher,
    check_secret_hash,
    check_session_key_hash,
    make_secret_hash,
    make_session_key_hash,
)
from netbox_secrets.utils import generate_random_key


class SessionKeyHashTestCase(SimpleTestCase):
    def test_roundtrip(self):
        key = generate_random_key()
        encoded = make_session_key_hash(key)
        self.assertTrue(encoded.startswith('sha256$'))
        self.assertLessEqual(len(encoded), 128)
        self.assertTrue(check_session_key_hash(key, encoded))

    def test_wrong_key(self):
        encoded = make_session_key_hash(generate_random_key())
        self.assertFalse(check_session_key_hash(generate_random_key(), encoded))

    def test_legacy_hash_is_rejected(self):
        key = generate_random_key()
        self.assertFalse(check_session_key_hash(key, make_password(key.hex())))

    def test_unknown_format_is_invalid(self):
        self.assertFalse(check_session_key_hash(generate_random_key(), 'invalid'))

    def test_does_not_warn(self):
        key = generate_random_key()
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            check_session_key_hash(key, make_session_key_hash(key))
            check_session_key_hash(key, make_password(key.hex()))


class SecretHashTestCase(SimpleTestCase):
    def test_roundtrip(self):
        key = generate_random_key()
        encoded = make_secret_hash('hunter2', key)
        self.assertTrue(encoded.startswith('hmac_sha256$'))
        self.assertEqual(len(encoded.split('$')), 3)
        self.assertLessEqual(len(encoded), 128)
        self.assertTrue(check_secret_hash('hunter2', key, encoded))
        self.assertFalse(check_secret_hash('hunter3', key, encoded))

    def test_same_value_gives_different_hashes_that_both_validate(self):
        key = generate_random_key()
        first = make_secret_hash('hunter2', key)
        second = make_secret_hash('hunter2', key)
        self.assertNotEqual(first, second)
        self.assertTrue(check_secret_hash('hunter2', key, first))
        self.assertTrue(check_secret_hash('hunter2', key, second))

    def test_malformed_hash_is_invalid(self):
        key = generate_random_key()
        self.assertFalse(check_secret_hash('hunter2', key, 'hmac_sha256$' + 'a' * 64))

    def test_hash_is_keyed(self):
        self.assertNotEqual(
            make_secret_hash('hunter2', generate_random_key()),
            make_secret_hash('hunter2', generate_random_key()),
        )
        encoded = make_secret_hash('hunter2', generate_random_key())
        self.assertFalse(check_secret_hash('hunter2', generate_random_key(), encoded))

    def test_unicode_plaintext(self):
        key = generate_random_key()
        encoded = make_secret_hash('pässwörd-✓', key)
        self.assertTrue(check_secret_hash('pässwörd-✓', key, encoded))

    def test_current_hash_does_not_warn(self):
        key = generate_random_key()
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            check_secret_hash('hunter2', key, make_secret_hash('hunter2', key))


class LegacySecretHashTestCase(SimpleTestCase):
    def test_legacy_hash_is_still_accepted_with_deprecation_warning(self):
        legacy = make_password('hunter2', hasher=SecretValidationHasher())
        with self.assertWarnsRegex(DeprecationWarning, r"secret hashes .* removed in NetBox v4\.8"):
            self.assertTrue(check_secret_hash('hunter2', generate_random_key(), legacy))

    def test_legacy_hash_wrong_plaintext(self):
        legacy = make_password('hunter2', hasher=SecretValidationHasher())
        with self.assertWarns(DeprecationWarning):
            self.assertFalse(check_secret_hash('nope', generate_random_key(), legacy))
