import base64
from unittest import mock

from Crypto.PublicKey import RSA
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import ProtectedError

from netbox_secrets.constants import CENSOR_MASTER_KEY, CENSOR_MASTER_KEY_CHANGED
from netbox_secrets.exceptions import InvalidKey
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY
from netbox_secrets.utils import decrypt_master_key, encrypt_master_key, generate_random_key
from utilities.testing import TestCase, create_test_device


class UserKeyModelTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(username='alice')
        cls.other_user = User.objects.create_user(username='bob')

    def test_str_and_flags(self):
        userkey = UserKey(user=self.user)
        self.assertEqual(str(userkey), self.user.username)
        self.assertFalse(userkey.is_filled())
        self.assertFalse(userkey.is_active())

        userkey.public_key = PUBLIC_KEY
        self.assertTrue(userkey.is_filled())

    def test_clean_invalid_key_formats(self):
        userkey = UserKey(user=self.user, public_key="not-a-key")
        with self.assertRaises(ValidationError):
            userkey.clean()

    def test_clean_import_key_exception(self):
        with mock.patch('netbox_secrets.models.keys.RSA.import_key', side_effect=Exception("boom")):
            userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
            with self.assertRaises(ValidationError):
                userkey.clean()

    def test_clean_no_public_key(self):
        userkey = UserKey(user=self.user, public_key="")
        userkey.clean()

    def test_clean_key_size_validation(self):
        # Too small
        small_key = RSA.generate(1024).publickey().export_key('PEM')
        with self.assertRaises(ValidationError):
            UserKey(user=self.user, public_key=small_key).clean()

        # Too large (mocked)
        with mock.patch('netbox_secrets.models.keys.RSA.import_key') as import_key:
            fake_key = mock.Mock()
            fake_key.size_in_bits.return_value = 9000
            import_key.return_value = fake_key
            with self.assertRaises(ValidationError):
                UserKey(user=self.user, public_key=PUBLIC_KEY).clean()

    def test_clean_public_key_change_blocked_with_secrets(self):
        # Create active key for current user
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        self.assertTrue(userkey.is_active())

        # Create a Secret to enforce restriction
        role = SecretRole.objects.create(name='Role', slug='role')
        device = create_test_device('device-1')
        secret = Secret(
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
            role=role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        secret.save()

        # Changing public key should be blocked as this is the only active key
        userkey.public_key = RSA.generate(2048).publickey().export_key('PEM')
        with self.assertRaises(ValidationError):
            userkey.clean()

    def test_clean_public_key_change_allowed_with_other_active_key(self):
        # Ensure another active key exists
        active_key = UserKey.objects.create(user=self.other_user, public_key=PUBLIC_KEY)
        self.assertTrue(active_key.is_active())

        # Create inactive key for current user (no auto-activation because active exists)
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        self.assertFalse(userkey.is_active())

        # Now public key change should not raise (no secrets needed for this path)
        userkey.public_key = RSA.generate(2048).publickey().export_key('PEM')
        userkey.clean()

    def test_save_invalidates_master_key_cipher(self):
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        self.assertTrue(userkey.is_active())
        self.assertIsNotNone(userkey.master_key_cipher)

        # Reload to ensure initial values are captured for change detection
        userkey = UserKey.objects.get(pk=userkey.pk)
        userkey.public_key = RSA.generate(2048).publickey().export_key('PEM')
        userkey.save()
        self.assertIsNone(userkey.master_key_cipher)

    def test_activate_requires_public_key(self):
        userkey = UserKey(user=self.user)
        with self.assertRaises(ValueError):
            userkey.activate(generate_random_key())

    def test_get_master_key(self):
        master_key = generate_random_key()
        userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
        userkey.activate(master_key)

        self.assertEqual(userkey.get_master_key(PRIVATE_KEY), master_key)
        self.assertIsNone(userkey.get_master_key(b'invalid-private-key'))

        inactive_key = UserKey(user=self.other_user, public_key=PUBLIC_KEY)
        with self.assertRaises(ValueError):
            inactive_key.get_master_key(PRIVATE_KEY)

    def test_delete_last_active_key_with_secrets(self):
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        role = SecretRole.objects.create(name='Role2', slug='role2')
        device = create_test_device('device-2')
        secret = Secret(
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
            role=role,
            name='secret2',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        secret.save()

        with self.assertRaises(ProtectedError):
            userkey.delete()

    def test_queryset_bulk_delete_blocked(self):
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        with self.assertRaisesRegex(PermissionDenied, "Bulk deletion disabled for UserKey"):
            UserKey.objects.all().delete()

    def test_queryset_active(self):
        other_user = get_user_model().objects.create_user(username='active-user')
        active_key = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        inactive_user = get_user_model().objects.create_user(username='inactive-user')
        # Prevent auto-activation by ensuring an active key already exists
        inactive_key = UserKey.objects.create(user=inactive_user, public_key=PUBLIC_KEY)
        self.assertIn(active_key, list(UserKey.objects.active()))
        self.assertNotIn(inactive_key, list(UserKey.objects.active()))

    def test_to_objectchange_censors_master_key_cipher(self):
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        userkey.snapshot()
        userkey.public_key = RSA.generate(2048).publickey().export_key('PEM')
        userkey.save()

        objectchange = userkey.to_objectchange('update')
        self.assertEqual(objectchange.prechange_data['master_key_cipher'], CENSOR_MASTER_KEY)
        self.assertEqual(objectchange.postchange_data['master_key_cipher'], CENSOR_MASTER_KEY_CHANGED)


class SessionKeyModelTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(username='charlie')
        cls.userkey = UserKey.objects.create(user=cls.user, public_key=PUBLIC_KEY)
        cls.master_key = cls.userkey.get_master_key(PRIVATE_KEY)

    def test_save_requires_master_key(self):
        session_key = SessionKey(userkey=self.userkey)
        with self.assertRaises(ValueError):
            session_key.save()

    def test_save_and_retrieve_master_key(self):
        session_key = SessionKey(userkey=self.userkey)
        session_key.save(master_key=self.master_key)
        self.assertIsNotNone(session_key.key)
        self.assertEqual(session_key.get_master_key(session_key.key), self.master_key)
        with self.assertRaises(InvalidKey):
            session_key.get_master_key(b'wrong-session-key')

    def test_get_session_key(self):
        session_key = SessionKey(userkey=self.userkey)
        session_key.save(master_key=self.master_key)
        recovered = session_key.get_session_key(self.master_key)
        self.assertEqual(recovered, session_key.key)
        wrong_master = b'x' * len(self.master_key)
        with self.assertRaises(InvalidKey):
            session_key.get_session_key(wrong_master)

    def test_str(self):
        session_key = SessionKey(userkey=self.userkey)
        self.assertIn(self.userkey.user.username, str(session_key))


class SecretRoleModelTestCase(TestCase):
    def test_str(self):
        role = SecretRole.objects.create(name='Role', slug='role')
        self.assertEqual(str(role), 'Role')


class SecretModelTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-3')
        cls.secret_key = generate_random_key()

    def _create_secret(self, plaintext="secret"):
        secret = Secret(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='test-secret',
            plaintext=plaintext,
        )
        return secret

    def test_str_default(self):
        secret = self._create_secret()
        secret.encrypt(self.secret_key)
        secret.save()
        secret.name = ""
        secret.save()
        self.assertIn("Secret #", str(secret))

    def test_save_sets_object_repr(self):
        secret = self._create_secret()
        secret.encrypt(self.secret_key)
        secret.save()
        self.assertEqual(secret._object_repr, str(self.device)[:200])

    def test_pad_unpad(self):
        secret = self._create_secret(plaintext="abc")
        padded = secret._pad("abc")
        self.assertEqual(secret._unpad(padded), "abc")

        long_plaintext = "a" * 70
        padded_long = secret._pad(long_plaintext)
        self.assertEqual(secret._unpad(padded_long), long_plaintext)

        too_large = "a" * (secret.MAX_SECRET_SIZE + 1)
        with self.assertRaises(ValueError):
            secret._pad(too_large)

    def test_encrypt_decrypt(self):
        secret = self._create_secret(plaintext="supersecret")
        secret.encrypt(self.secret_key)
        self.assertIsNone(secret.plaintext)
        self.assertTrue(secret.ciphertext)
        self.assertTrue(secret.hash)
        self.assertTrue(secret.validate("supersecret"))
        self.assertFalse(secret.validate("wrong"))

        secret.decrypt(self.secret_key)
        self.assertEqual(secret.plaintext, "supersecret")

        # Decrypt is a no-op if plaintext already populated
        secret.decrypt(self.secret_key)

    def test_encrypt_without_plaintext(self):
        secret = self._create_secret()
        secret.plaintext = None
        with self.assertRaises(ValueError):
            secret.encrypt(self.secret_key)

    def test_decrypt_without_ciphertext(self):
        secret = self._create_secret()
        secret.plaintext = None
        secret.ciphertext = b""
        with self.assertRaises(ValueError):
            secret.decrypt(self.secret_key)

    def test_decrypt_invalid_hash(self):
        secret = self._create_secret(plaintext="supersecret")
        secret.encrypt(self.secret_key)
        secret.hash = "invalid-hash"
        with self.assertRaises(ValueError):
            secret.decrypt(self.secret_key)

    def test_validate_requires_hash(self):
        secret = self._create_secret(plaintext="supersecret")
        secret.hash = ""
        with self.assertRaises(ValueError):
            secret.validate("supersecret")


class CryptoUtilsTestCase(TestCase):
    def test_encrypt_decrypt_master_key(self):
        master_key = generate_random_key()
        cipher = encrypt_master_key(master_key, PUBLIC_KEY)
        self.assertEqual(decrypt_master_key(cipher, PRIVATE_KEY), master_key)

    def test_generate_random_key_invalid_bits(self):
        with self.assertRaises(Exception):
            generate_random_key(bits=255)

    def test_generate_random_key_valid_bits(self):
        key = generate_random_key(bits=256)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(base64.b64encode(key), bytes)
