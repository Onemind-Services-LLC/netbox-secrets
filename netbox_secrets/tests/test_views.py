import base64
from unittest import mock

from Crypto.PublicKey import RSA
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory
from django.urls import reverse

from netbox_secrets import views as plugin_views
from netbox_secrets.forms import SecretForm
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY
from utilities.testing import TestCase, create_test_device


class SecretRoleViewTestCase(TestCase):
    user_permissions = (
        'netbox_secrets.view_secretrole',
        'netbox_secrets.view_secret',
    )

    @classmethod
    def setUpTestData(cls):
        cls.parent = SecretRole.objects.create(name='Parent', slug='parent')
        cls.child = SecretRole.objects.create(name='Child', slug='child', parent=cls.parent)

    def test_get_extra_context(self):
        request = RequestFactory().get('/')
        request.user = self.user
        view = plugin_views.SecretRoleView()
        ctx = view.get_extra_context(request, self.parent)
        self.assertIn('related_models', ctx)

    def test_secret_role_children(self):
        role = SecretRole.objects.create(name='Role', slug='role')
        device = create_test_device('device-view')
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
            role=role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        request = RequestFactory().get('/')
        request.user = self.user
        view = plugin_views.SecretRoleSecretView()
        queryset = view.get_children(request, role)
        self.assertIn(secret, list(queryset))

    def test_secret_view_extra_context(self):
        role = SecretRole.objects.create(name='Role2', slug='role2')
        device = create_test_device('device-view-2')
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
            role=role,
            name='secret2',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        request = RequestFactory().get('/')
        request.user = self.user
        view = plugin_views.SecretView()
        ctx = view.get_extra_context(request, secret)
        self.assertIn('related_models', ctx)


class SecretEditViewAccessTestCase(TestCase):
    user_permissions = (
        'netbox_secrets.add_secret',
        'netbox_secrets.view_secret',
    )

    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-edit')

    def test_redirect_when_no_userkey(self):
        url = reverse('plugins:netbox_secrets:secret_add')
        response = self.client.get(
            f"{url}?assigned_object_type={ContentType.objects.get_for_model(self.device).pk}"
            f"&assigned_object_id={self.device.pk}"
        )
        self.assertHttpStatus(response, 302)
        self.assertIn(reverse('plugins:netbox_secrets:userkey_add'), response.url)

    def test_redirect_when_userkey_inactive(self):
        # Create another active key to prevent auto-activation
        other_user = get_user_model().objects.create_user(username='other')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)

        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        self.assertFalse(userkey.is_active())

        url = reverse('plugins:netbox_secrets:secret_add')
        response = self.client.get(
            f"{url}?assigned_object_type={ContentType.objects.get_for_model(self.device).pk}"
            f"&assigned_object_id={self.device.pk}"
        )
        self.assertHttpStatus(response, 302)
        self.assertIn(reverse('plugins:netbox_secrets:userkey', kwargs={'pk': userkey.pk}), response.url)


class SecretEditViewPostTestCase(TestCase):
    user_permissions = (
        'netbox_secrets.add_secret',
        'netbox_secrets.view_secret',
        'netbox_secrets.change_secret',
        'netbox_secrets.view_secretrole',
    )

    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-post')

    def setUp(self):
        super().setUp()
        self.userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        master_key = self.userkey.get_master_key(PRIVATE_KEY)
        self.session_key = SessionKey(userkey=self.userkey)
        self.session_key.save(master_key=master_key)
        self.session_key_b64 = base64.b64encode(self.session_key.key).decode('utf-8')

    def _post_data(self, plaintext='secret', plaintext2='secret', include_session_key=False, extra=None):
        data = {
            'name': 'secret',
            'role': self.role.pk,
            'plaintext': plaintext,
            'plaintext2': plaintext2,
        }
        if include_session_key:
            data['session_key'] = self.session_key_b64
        if extra:
            data.update(extra)
        return data

    def _post_url(self):
        return (
            f"{reverse('plugins:netbox_secrets:secret_add')}"
            f"?assigned_object_type={ContentType.objects.get_for_model(self.device).pk}"
            f"&assigned_object_id={self.device.pk}"
        )

    def test_post_missing_session_key(self):
        response = self.client.post(self._post_url(), data=self._post_data())
        self.assertHttpStatus(response, 200)
        form_errors = response.context['form'].non_field_errors()
        self.assertTrue(any("No session key was provided with the request" in err for err in form_errors))

    def test_post_invalid_session_key(self):
        bad_key = base64.b64encode(b'wrong-key').decode('utf-8')
        response = self.client.post(
            self._post_url(),
            data=self._post_data(include_session_key=True, extra={'session_key': bad_key}),
        )
        self.assertHttpStatus(response, 200)
        form_errors = response.context['form'].non_field_errors()
        self.assertTrue(any("Invalid session key provided" in err for err in form_errors))

    def test_post_missing_session_key_record(self):
        SessionKey.objects.filter(userkey=self.userkey).delete()
        response = self.client.post(
            self._post_url(),
            data=self._post_data(include_session_key=True),
        )
        self.assertHttpStatus(response, 200)
        form_errors = response.context['form'].non_field_errors()
        self.assertTrue(any("No session key found for this user." in err for err in form_errors))

    def test_post_form_invalid(self):
        response = self.client.post(
            self._post_url(),
            data=self._post_data(plaintext='one', plaintext2='two'),
        )
        self.assertHttpStatus(response, 200)

    def test_post_success(self):
        response = self.client.post(
            self._post_url(),
            data=self._post_data(include_session_key=True),
        )
        self.assertHttpStatus(response, 302)
        self.assertTrue(Secret.objects.filter(name='secret').exists())

    def test_post_add_another(self):
        response = self.client.post(
            self._post_url(),
            data=self._post_data(include_session_key=True, extra={'_addanother': '1'}),
        )
        self.assertHttpStatus(response, 302)
        self.assertIn('assigned_object_type', response.url)

    def test_post_add_another_with_return_url(self):
        response = self.client.post(
            f"{self._post_url()}&return_url=/plugins/secrets/secrets/",
            data=self._post_data(include_session_key=True, extra={'_addanother': '1'}),
        )
        self.assertHttpStatus(response, 302)
        self.assertIn('return_url', response.url)

    def test_post_abort_request(self):
        from utilities.exceptions import AbortRequest

        with mock.patch.object(SecretForm, 'save', side_effect=AbortRequest("boom")):
            response = self.client.post(
                self._post_url(),
                data=self._post_data(include_session_key=True),
            )
            self.assertHttpStatus(response, 200)

    def test_post_edit_calls_snapshot(self):
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-edit',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        url = reverse('plugins:netbox_secrets:secret_edit', kwargs={'pk': secret.pk})
        with mock.patch.object(Secret, 'snapshot', autospec=True) as snapshot:
            response = self.client.post(url, data={'name': 'secret-edit', 'role': self.role.pk})
        self.assertHttpStatus(response, 302)
        snapshot.assert_called_once()

    def test_post_without_absolute_url(self):
        class _RaiseAttributeError:
            def __get__(self, obj, objtype=None):
                raise AttributeError

        with mock.patch.object(Secret, 'get_absolute_url', new=_RaiseAttributeError()):
            response = self.client.post(
                self._post_url(),
                data=self._post_data(include_session_key=True),
            )
        self.assertHttpStatus(response, 302)


class UserKeyViewTestCase(TestCase):
    user_permissions = (
        'netbox_secrets.view_userkey',
        'netbox_secrets.add_userkey',
        'netbox_secrets.change_userkey',
    )

    def test_userkey_edit_get(self):
        response = self.client.get(reverse('plugins:netbox_secrets:userkey_add'))
        self.assertHttpStatus(response, 200)

    def test_userkey_list_extra_context(self):
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        request = RequestFactory().get('/')
        request.user = self.user
        view = plugin_views.UserKeyListView()
        context = view.get_extra_context(request)
        self.assertIn('user_key', context)

    def test_userkey_list_activate_button_visible_for_active_key(self):
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.get(reverse('plugins:netbox_secrets:userkey_list'))
        self.assertContains(response, 'Activate User Key')

    def test_userkey_list_activate_button_hidden_without_key(self):
        response = self.client.get(reverse('plugins:netbox_secrets:userkey_list'))
        self.assertNotContains(response, 'Activate User Key')

    def test_userkey_list_activate_button_hidden_for_inactive_key(self):
        other_user = get_user_model().objects.create_user(username='list-active-owner')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.get(reverse('plugins:netbox_secrets:userkey_list'))
        self.assertNotContains(response, 'Activate User Key')

    def test_userkey_edit_post_valid(self):
        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_add'),
            data={'public_key': PUBLIC_KEY},
        )
        self.assertHttpStatus(response, 302)
        self.assertTrue(UserKey.objects.filter(user=self.user).exists())

    def test_userkey_edit_post_invalid(self):
        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_add'),
            data={'public_key': 'invalid'},
        )
        self.assertHttpStatus(response, 200)
        self.assertFalse(UserKey.objects.filter(user=self.user).exists())


class ActivateUserKeyViewTestCase(TestCase):
    user_permissions = ('netbox_secrets.change_userkey',)

    def test_activate_get(self):
        response = self.client.get(reverse('plugins:netbox_secrets:userkey_activate'))
        self.assertHttpStatus(response, 200)

    def test_activate_requires_permission(self):
        self.remove_permissions('netbox_secrets.change_userkey')
        response = self.client.post(reverse('plugins:netbox_secrets:userkey_activate'))
        self.assertHttpStatus(response, 403)

    def test_activate_inactive_userkey(self):
        # Create another active key to prevent auto-activation
        other_user = get_user_model().objects.create_user(username='other2')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.post(reverse('plugins:netbox_secrets:userkey_activate'))
        self.assertHttpStatus(response, 302)

    def test_activate_success(self):
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        other_user = get_user_model().objects.create_user(username='other3')
        target_key = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)

        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_activate'),
            data={'secret_key': PRIVATE_KEY, 'user_keys': [target_key.pk]},
        )
        self.assertHttpStatus(response, 302)
        target_key.refresh_from_db()
        self.assertTrue(target_key.is_active())

    def test_activate_invalid_key(self):
        bad_public = RSA.generate(2048).publickey().export_key('PEM')
        UserKey.objects.create(user=self.user, public_key=bad_public)
        other_user = get_user_model().objects.create_user(username='other-invalid')
        target_key = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        response = self.client.post(
            reverse('plugins:netbox_secrets:userkey_activate'),
            data={'secret_key': PRIVATE_KEY, 'user_keys': [target_key.pk]},
        )
        self.assertHttpStatus(response, 200)
        self.assertIn("Invalid Private Key", response.content.decode())
