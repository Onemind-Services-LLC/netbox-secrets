from unittest import mock

from Crypto.PublicKey import RSA
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from netbox_secrets.forms import (
    ActivateUserKeyForm,
    SecretForm,
    SecretRoleForm,
    UserKeyForm,
)
from netbox_secrets.forms.bulk_edit import SecretBulkEditForm, SecretRoleBulkEditForm
from netbox_secrets.forms.bulk_import import SecretRoleImportForm
from netbox_secrets.forms.filterset import SecretFilterForm, SecretRoleFilterForm
from netbox_secrets.forms.model_forms import validate_rsa_key
from netbox_secrets.models import Secret, SecretRole, UserKey
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY, SSH_PUBLIC_KEY
from utilities.testing import create_test_device


class RSAValidationTestCase(TestCase):
    def test_validate_rsa_key_empty(self):
        with self.assertRaises(Exception):
            validate_rsa_key("", is_secret=False)

    def test_validate_rsa_key_openssh(self):
        with self.assertRaises(Exception):
            validate_rsa_key(SSH_PUBLIC_KEY, is_secret=False)

    def test_validate_rsa_key_invalid(self):
        with self.assertRaises(Exception):
            validate_rsa_key("not-a-key", is_secret=False)

    def test_validate_rsa_key_small(self):
        small_key = RSA.generate(1024).export_key('PEM').decode('utf-8')
        with self.assertRaises(Exception):
            validate_rsa_key(small_key, is_secret=True)

    def test_validate_rsa_key_wrong_type(self):
        with self.assertRaises(Exception):
            validate_rsa_key(PUBLIC_KEY, is_secret=True)
        with self.assertRaises(Exception):
            validate_rsa_key(PRIVATE_KEY, is_secret=False)

    def test_validate_rsa_key_oaep_error(self):
        with mock.patch('netbox_secrets.forms.model_forms.PKCS1_OAEP.new', side_effect=Exception("boom")):
            with self.assertRaises(Exception):
                validate_rsa_key(PUBLIC_KEY, is_secret=False)

    def test_validate_rsa_key_import_error(self):
        with mock.patch('netbox_secrets.forms.model_forms.RSA.importKey', side_effect=Exception("boom")):
            with self.assertRaises(Exception):
                validate_rsa_key(PUBLIC_KEY, is_secret=False)

    def test_validate_rsa_key_valid(self):
        self.assertIsNotNone(validate_rsa_key(PUBLIC_KEY, is_secret=False))
        self.assertIsNotNone(validate_rsa_key(PRIVATE_KEY, is_secret=True))


class SecretRoleFormTestCase(TestCase):
    def test_secret_role_form_valid(self):
        parent = SecretRole.objects.create(name='Parent', slug='parent')
        form = SecretRoleForm(data={'name': 'Child', 'slug': 'child', 'parent': parent.pk})
        self.assertTrue(form.is_valid())
        role = form.save()
        self.assertEqual(role.parent, parent)


class SecretFormTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-form')

    def _instance(self):
        return Secret(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )

    def test_secret_form_plaintext_required_for_new(self):
        form = SecretForm(
            data={'name': 's1', 'role': self.role.pk, 'plaintext': '', 'plaintext2': ''},
            instance=self._instance(),
        )
        self.assertFalse(form.is_valid())

    def test_secret_form_plaintext_mismatch(self):
        form = SecretForm(
            data={'name': 's2', 'role': self.role.pk, 'plaintext': 'a', 'plaintext2': 'b'},
            instance=self._instance(),
        )
        self.assertFalse(form.is_valid())

    def test_secret_form_plaintext_whitespace(self):
        form = SecretForm(
            data={'name': 's4', 'role': self.role.pk, 'plaintext': '   ', 'plaintext2': '   '},
            instance=self._instance(),
        )
        self.assertFalse(form.is_valid())

    def test_secret_form_clean_plaintext_empty(self):
        form = SecretForm(
            data={'name': 's5', 'role': self.role.pk, 'plaintext': 'x', 'plaintext2': 'x'},
            instance=self._instance(),
        )
        form.cleaned_data = {'plaintext': '   '}
        with self.assertRaises(Exception):
            form.clean_plaintext()

    def test_secret_form_valid(self):
        form = SecretForm(
            data={'name': 's3', 'role': self.role.pk, 'plaintext': 'secret', 'plaintext2': 'secret'},
            instance=self._instance(),
        )
        self.assertTrue(form.is_valid())


class UserKeyFormTestCase(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='user1')
        self.userkey = UserKey(user=self.user)

    def test_userkey_form_valid(self):
        form = UserKeyForm(data={'public_key': PUBLIC_KEY}, instance=self.userkey)
        self.assertTrue(form.is_valid())

    def test_userkey_form_invalid(self):
        form = UserKeyForm(data={'public_key': SSH_PUBLIC_KEY}, instance=self.userkey)
        self.assertFalse(form.is_valid())

    def test_userkey_form_empty(self):
        form = UserKeyForm(data={'public_key': '   '}, instance=self.userkey)
        self.assertFalse(form.is_valid())

    def test_userkey_clean_public_key_empty(self):
        form = UserKeyForm(data={'public_key': PUBLIC_KEY}, instance=self.userkey)
        form.cleaned_data = {'public_key': '   '}
        with self.assertRaises(Exception):
            form.clean_public_key()


class ActivateUserKeyFormTestCase(TestCase):
    def test_activate_user_key_form_valid(self):
        user = get_user_model().objects.create_user(username='user2')
        other_user = get_user_model().objects.create_user(username='user2-active')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        userkey = UserKey.objects.create(user=user, public_key=PUBLIC_KEY)
        self.assertFalse(userkey.is_active())
        form = ActivateUserKeyForm(data={'secret_key': PRIVATE_KEY, 'user_keys': [userkey.pk]})
        self.assertTrue(form.is_valid())

    def test_activate_user_key_form_invalid(self):
        form = ActivateUserKeyForm(data={'secret_key': 'bad', 'user_keys': []})
        self.assertFalse(form.is_valid())

    def test_activate_user_key_form_empty_key(self):
        form = ActivateUserKeyForm(data={'secret_key': '   ', 'user_keys': []})
        self.assertFalse(form.is_valid())

    def test_activate_user_key_clean_secret_key_empty(self):
        form = ActivateUserKeyForm(data={'secret_key': PRIVATE_KEY, 'user_keys': []})
        form.cleaned_data = {'secret_key': '   '}
        with self.assertRaises(Exception):
            form.clean_secret_key()


class BulkFormsTestCase(TestCase):
    def test_bulk_edit_forms(self):
        SecretRoleBulkEditForm()
        SecretBulkEditForm()

    def test_bulk_import_form(self):
        SecretRoleImportForm()


class FilterFormsTestCase(TestCase):
    def test_filter_forms(self):
        SecretRoleFilterForm()
        SecretFilterForm()
