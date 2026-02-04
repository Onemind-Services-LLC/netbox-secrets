import base64
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from rest_framework import status
from rest_framework.parsers import FormParser
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from netbox_secrets.api import serializers, views as api_views
from netbox_secrets.constants import SESSION_COOKIE_NAME
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY
from utilities.testing import APITestCase, TestCase, create_test_device


class SerializerTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(username='serializer-user')
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-serializer')

    def test_userkey_serializer_create_and_update(self):
        factory = APIRequestFactory()
        request = factory.post('/')
        request.user = self.user

        serializer = serializers.UserKeySerializer(data={'public_key': PUBLIC_KEY}, context={'request': request})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        userkey = serializer.save()
        self.assertEqual(userkey.user, self.user)

        update = serializers.UserKeySerializer(
            userkey,
            data={'public_key': PUBLIC_KEY, 'private_key': PRIVATE_KEY},
            context={'request': request},
            partial=True,
        )
        self.assertTrue(update.is_valid(), update.errors)
        updated = update.save()
        self.assertEqual(updated.user, self.user)

    def test_session_key_serializer(self):
        userkey = UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        master_key = userkey.get_master_key(PRIVATE_KEY)
        session_key = SessionKey(userkey=userkey)
        session_key.save(master_key=master_key)
        request = APIRequestFactory().get('/')
        request.user = self.user

        serializer = serializers.SessionKeySerializer(session_key, context={'session_key': 'abc', 'request': request})
        self.assertEqual(serializer.data['session_key'], 'abc')

        session_key.key = b'raw'
        serializer = serializers.SessionKeySerializer(session_key, context={'request': request})
        self.assertEqual(serializer.data['session_key'], base64.b64encode(b'raw').decode('utf-8'))

    def test_activate_user_key_serializer(self):
        serializer = serializers.ActivateUserKeySerializer(data={'private_key': PRIVATE_KEY, 'user_key_ids': [1, 1, 2]})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data['user_key_ids'], [1, 2])

    def test_secret_serializer_encryption(self):
        master_key = b'x' * 32
        serializer = serializers.SecretSerializer(
            data={
                'assigned_object_type': 'dcim.device',
                'assigned_object_id': self.device.pk,
                'role': self.role.pk,
                'name': 'secret',
                'plaintext': 'clear',
            },
            context={'request': None, 'master_key': master_key},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertIn('ciphertext', serializer.validated_data)
        self.assertIn('hash', serializer.validated_data)
        self.assertNotIn('plaintext', serializer.validated_data)

    def test_secret_serializer_requires_master_key(self):
        serializer = serializers.SecretSerializer(
            data={
                'assigned_object_type': 'dcim.device',
                'assigned_object_id': self.device.pk,
                'role': self.role.pk,
                'name': 'secret',
                'plaintext': 'clear',
            },
            context={'request': None},
        )
        self.assertFalse(serializer.is_valid())

    def test_secret_serializer_assigned_object(self):
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        request = APIRequestFactory().get('/')
        request.user = self.user
        serializer = serializers.SecretSerializer(secret, context={'request': request})
        self.assertIsNotNone(serializer.data.get('assigned_object'))

    def test_secret_serializer_get_assigned_object(self):
        request = APIRequestFactory().get('/')
        request.user = self.user
        serializer = serializers.SecretSerializer(context={'request': request})

        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-assigned',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        self.assertIsNotNone(serializer.get_assigned_object(secret))

        missing_secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=999999,
            role=self.role,
            name='secret-missing',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        self.assertIsNone(serializer.get_assigned_object(missing_secret))


class BaseAPITestCase(APITestCase):
    user_permissions = (
        'netbox_secrets.view_userkey',
        'netbox_secrets.add_userkey',
        'netbox_secrets.change_userkey',
        'netbox_secrets.delete_userkey',
        'netbox_secrets.view_sessionkey',
        'netbox_secrets.add_sessionkey',
        'netbox_secrets.change_sessionkey',
        'netbox_secrets.delete_sessionkey',
        'netbox_secrets.view_secretrole',
        'netbox_secrets.add_secretrole',
        'netbox_secrets.change_secretrole',
        'netbox_secrets.delete_secretrole',
        'netbox_secrets.view_secret',
        'netbox_secrets.add_secret',
        'netbox_secrets.change_secret',
        'netbox_secrets.delete_secret',
    )
    view_namespace = 'plugins-api:netbox_secrets'

    @classmethod
    def setUpTestData(cls):
        cls.device = create_test_device('device-api')
        cls.role = SecretRole.objects.create(name='Role', slug='role')

    def create_userkey(self, user=None):
        user = user or self.user
        return UserKey.objects.create(user=user, public_key=PUBLIC_KEY)

    def create_session_key(self, user=None):
        user = user or self.user
        userkey = UserKey.objects.filter(user=user).first() or self.create_userkey(user=user)
        master_key = userkey.get_master_key(PRIVATE_KEY)
        session_key = SessionKey(userkey=userkey)
        session_key.save(master_key=master_key)
        return session_key, base64.b64encode(session_key.key).decode('utf-8')


class SecretsRootAPITestCase(BaseAPITestCase):
    def test_root(self):
        url = reverse('plugins-api:netbox_secrets-api:api-root')
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_root_view_name(self):
        self.assertEqual(api_views.SecretsRootView().get_view_name(), 'Secrets')


class UserKeyAPITestCase(BaseAPITestCase):
    def test_userkey_crud(self):
        url = reverse('plugins-api:netbox_secrets-api:userkey-list')
        response = self.client.post(url, data={'public_key': PUBLIC_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        userkey_id = response.data['id']

        detail = reverse('plugins-api:netbox_secrets-api:userkey-detail', kwargs={'pk': userkey_id})
        response = self.client.get(detail, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

        response = self.client.patch(detail, data={'public_key': PUBLIC_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

        response = self.client.delete(detail, **self.header)
        self.assertHttpStatus(response, status.HTTP_204_NO_CONTENT)

    def test_userkey_activate_permission_denied(self):
        self.remove_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_key_ids': []}, **self.header)
        self.assertHttpStatus(response, status.HTTP_403_FORBIDDEN)

    def test_userkey_activate_missing_admin_key(self):
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_key_ids': [1]}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_userkey_activate_inactive_admin_key(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        other_user = get_user_model().objects.create_user(username='other-key')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_key_ids': [1]}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_userkey_activate_invalid_private_key(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        target_user = get_user_model().objects.create_user(username='target')
        target_key = UserKey.objects.create(user=target_user, public_key=PUBLIC_KEY)
        response = self.client.post(
            url, data={'private_key': 'invalid', 'user_key_ids': [target_key.pk]}, **self.header
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_userkey_activate_missing_ids(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_key_ids': []}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_userkey_activate_missing_keys(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_key_ids': [9999]}, **self.header)
        self.assertHttpStatus(response, status.HTTP_404_NOT_FOUND)

    def test_userkey_activate_success(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        target_user = get_user_model().objects.create_user(username='target2')
        target_key = UserKey.objects.create(user=target_user, public_key=PUBLIC_KEY)
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'user_key_ids': [target_key.pk]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_userkey_activate_exception(self):
        self.add_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:userkey-activate')
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        target_user = get_user_model().objects.create_user(username='target3')
        target_key = UserKey.objects.create(user=target_user, public_key=PUBLIC_KEY)
        with mock.patch.object(UserKey, 'activate', side_effect=Exception("boom")), mock.patch(
            'netbox_secrets.api.views.logger.exception'
        ):
            response = self.client.post(
                url,
                data={'private_key': PRIVATE_KEY, 'user_key_ids': [target_key.pk]},
                **self.header,
            )
            self.assertHttpStatus(response, status.HTTP_500_INTERNAL_SERVER_ERROR)


class SessionKeyAPITestCase(BaseAPITestCase):
    def test_session_key_list_empty(self):
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_404_NOT_FOUND)

    def test_session_key_list_with_key(self):
        self.create_userkey()
        self.create_session_key()
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_session_key_create_missing_userkey(self):
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_create_inactive_userkey(self):
        other_user = get_user_model().objects.create_user(username='inactive-owner')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_create_missing_private_key(self):
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(url, data={}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_create_invalid_private_key(self):
        self.create_userkey()
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(url, data={'private_key': 'invalid'}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_create_and_preserve(self):
        self.create_userkey()
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        session_key = response.data['session_key']

        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'preserve_key': True},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(response.data['session_key'], session_key)

    def test_session_key_preserve_invalid_hash(self):
        self.create_userkey()
        session_key, _ = self.create_session_key()
        SessionKey.objects.filter(pk=session_key.pk).update(hash='invalid')
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'preserve_key': True},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_delete(self):
        self.create_userkey()
        session_key, _ = self.create_session_key()
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.delete(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_204_NO_CONTENT)

    def test_session_key_delete_missing(self):
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = self.client.delete(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_404_NOT_FOUND)

    def test_session_key_cookie_session_auth(self):
        self.create_userkey()
        client = APIClient()
        client.force_login(self.user)
        url = reverse('plugins-api:netbox_secrets-api:sessionkey-list')
        response = client.post(url, data={'private_key': PRIVATE_KEY})
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertIn(SESSION_COOKIE_NAME, response.cookies)


class SecretRoleAPITestCase(BaseAPITestCase):
    def test_secretrole_crud(self):
        role = SecretRole.objects.create(name='Role2', slug='role2')
        role_id = role.pk

        detail = reverse('plugins-api:netbox_secrets-api:secretrole-detail', kwargs={'pk': role_id})
        response = self.client.get(detail, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)


class SecretAPITestCase(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.userkey = self.create_userkey()
        self.session_key, self.session_key_b64 = self.create_session_key()

    def _secret_payload(self, plaintext='secret'):
        return {
            'assigned_object_type': 'dcim.device',
            'assigned_object_id': self.device.pk,
            'role': {'id': self.role.pk},
            'name': 'secret',
            'plaintext': plaintext,
        }

    def test_create_requires_session_key(self):
        url = reverse('plugins-api:netbox_secrets-api:secret-list')
        response = self.client.post(url, data=self._secret_payload(), format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_create_with_session_key(self):
        url = reverse('plugins-api:netbox_secrets-api:secret-list')
        self.client.cookies[SESSION_COOKIE_NAME] = self.session_key_b64
        response = self.client.post(url, data=self._secret_payload(), format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.client.cookies.pop(SESSION_COOKIE_NAME, None)

    def test_retrieve_with_and_without_session_key(self):
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        url = reverse('plugins-api:netbox_secrets-api:secret-detail', kwargs={'pk': secret.pk})
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

        response = self.client.get(url, HTTP_X_SESSION_KEY=self.session_key_b64, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_list_with_session_key(self):
        Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-list',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        url = reverse('plugins-api:netbox_secrets-api:secret-list')
        response = self.client.get(url, HTTP_X_SESSION_KEY=self.session_key_b64, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_update_requires_session_key(self):
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-update',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        url = reverse('plugins-api:netbox_secrets-api:secret-detail', kwargs={'pk': secret.pk})
        response = self.client.patch(url, data={'plaintext': 'new'}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch(
            url,
            data={'plaintext': 'new'},
            HTTP_X_SESSION_KEY=self.session_key_b64,
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_invalid_session_key(self):
        url = reverse('plugins-api:netbox_secrets-api:secret-list')
        bad_key = base64.b64encode(b'wrong-key').decode('utf-8')
        response = self.client.post(
            url,
            data=self._secret_payload(),
            format='json',
            HTTP_X_SESSION_KEY=bad_key,
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_missing_session_key_record(self):
        SessionKey.objects.filter(userkey=self.userkey).delete()
        url = reverse('plugins-api:netbox_secrets-api:secret-list')
        response = self.client.post(
            url,
            data=self._secret_payload(),
            format='json',
            HTTP_X_SESSION_KEY=self.session_key_b64,
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_session_key_decode_error(self):
        viewset = api_views.SecretViewSet()
        request = APIRequestFactory().get('/', HTTP_X_SESSION_KEY='bad')
        viewset.request = request
        with mock.patch('netbox_secrets.api.views.base64.b64decode', side_effect=Exception):
            self.assertIsNone(viewset._get_session_key_from_request())

    def test_cookie_session_key_decode_error(self):
        viewset = api_views.SecretViewSet()
        request = APIRequestFactory().get('/')
        request.COOKIES[SESSION_COOKIE_NAME] = 'bad'
        viewset.request = request
        with mock.patch('netbox_secrets.api.views.base64.b64decode', side_effect=Exception):
            self.assertIsNone(viewset._get_session_key_from_request())

    def test_initial_unauthenticated(self):
        viewset = api_views.SecretViewSet()
        request = APIRequestFactory().get('/')
        request.user = AnonymousUser()
        drf_request = Request(request)
        viewset.request = drf_request
        viewset.action = 'list'
        with mock.patch.object(viewset, 'check_permissions', return_value=None), mock.patch.object(
            viewset, 'check_throttles', return_value=None
        ):
            viewset.initial(drf_request)
        self.assertIsNone(viewset.master_key)

    def test_list_unpaginated(self):
        Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-list-unpaginated',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        viewset = api_views.SecretViewSet()
        viewset.pagination_class = None
        request = APIRequestFactory().get('/')
        force_authenticate(request, user=self.user)
        drf_request = Request(request)
        viewset.request = drf_request
        viewset.action = 'list'
        viewset.kwargs = {}
        viewset.initial(drf_request)
        response = viewset.list(drf_request)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_decrypt_failure_silent(self):
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(self.device),
            assigned_object_id=self.device.pk,
            role=self.role,
            name='secret-bad-hash',
            ciphertext=b'0123456789abcdef' * 5,
            hash='invalid',
        )
        url = reverse('plugins-api:netbox_secrets-api:secret-detail', kwargs={'pk': secret.pk})
        response = self.client.get(url, HTTP_X_SESSION_KEY=self.session_key_b64, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)


class GenerateKeyPairAPITestCase(BaseAPITestCase):
    def test_generate_key_pair(self):
        url = reverse('plugins-api:netbox_secrets-api:generate-rsa-key-pair-list')
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertIn('public_key', response.data)

    def test_generate_key_pair_invalid(self):
        url = reverse('plugins-api:netbox_secrets-api:generate-rsa-key-pair-list')
        response = self.client.get(f'{url}?key_size=bad', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.get(f'{url}?key_size=1024', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)
        response = self.client.get(f'{url}?key_size=2050', **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_generate_key_pair_exception(self):
        viewset = api_views.GenerateRSAKeyPairView()
        request = APIRequestFactory().get('/api/plugins/secrets/generate-rsa-key-pair/')
        force_authenticate(request, user=self.user)
        drf_request = Request(request)
        viewset.request = drf_request
        with mock.patch('netbox_secrets.api.views.RSA.generate', side_effect=Exception("boom")), mock.patch(
            'netbox_secrets.api.views.logger.exception'
        ):
            response = viewset.list(drf_request)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class LegacyEndpointsAPITestCase(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.userkey = self.create_userkey()
        self.session_key, self.session_key_b64 = self.create_session_key()

    def test_legacy_session_keys_create_missing_private_key(self):
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.post(url, data={}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_session_keys_create_missing_userkey(self):
        user_key = UserKey.objects.get(user=self.user)
        user_key.delete()
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_session_keys_create_inactive_userkey(self):
        other_user = get_user_model().objects.create_user(username='legacy-inactive-owner')
        other_key = UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        master_key = self.userkey.get_master_key(PRIVATE_KEY)
        other_key.activate(master_key)
        user_key = UserKey.objects.get(user=self.user)
        user_key.delete()
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_session_keys_create_invalid_private_key(self):
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.post(url, data={'private_key': 'invalid'}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_session_keys_create_preserve(self):
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'preserve_key': True},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(response.data['session_key'], self.session_key_b64)

    def test_legacy_session_keys_create_sets_cookie(self):
        client = APIClient()
        client.force_login(self.user)
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = client.post(url, data={'private_key': PRIVATE_KEY})
        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertIn(SESSION_COOKIE_NAME, response.cookies)

    def test_legacy_session_keys(self):
        url = reverse('plugins-api:netbox_secrets-api:session-keys-list')
        response = self.client.get(url, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

        detail = reverse('plugins-api:netbox_secrets-api:session-keys-detail', kwargs={'pk': self.session_key.pk})
        response = self.client.get(detail, **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)

        response = self.client.delete(detail, **self.header)
        self.assertHttpStatus(response, status.HTTP_204_NO_CONTENT)

    def test_legacy_session_keys_get_queryset_anonymous(self):
        from netbox_secrets.api.views import LegacySessionKeyViewSet

        request = APIRequestFactory().get('/api/plugins/secrets/session-keys/')
        request.user = AnonymousUser()
        viewset = LegacySessionKeyViewSet()
        viewset.request = Request(request)
        queryset = viewset.get_queryset()
        self.assertIsNotNone(queryset)

    def test_legacy_activate_user_key(self):
        target_user = get_user_model().objects.create_user(username='legacy-target')
        target_key = UserKey.objects.create(user=target_user, public_key=PUBLIC_KEY)

        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'user_keys': [target_key.pk]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_200_OK)

    def test_legacy_activate_user_key_missing_admin(self):
        UserKey.objects.get(user=self.user).delete()
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'user_keys': [1]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_inactive_admin(self):
        UserKey.objects.get(user=self.user).delete()
        other_user = get_user_model().objects.create_user(username='legacy-other')
        UserKey.objects.create(user=other_user, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=self.user, public_key=PUBLIC_KEY)
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'user_keys': [1]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_invalid_private_key(self):
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(
            url,
            data={'private_key': 'invalid', 'user_keys': [1]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_missing_target(self):
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(
            url,
            data={'private_key': PRIVATE_KEY, 'user_keys': [9999]},
            **self.header,
        )
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_missing_ids(self):
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_keys': []}, **self.header)
        self.assertHttpStatus(response, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_permission_denied(self):
        self.remove_permissions('netbox_secrets.change_userkey')
        url = reverse('plugins-api:netbox_secrets-api:activate-user-key-list')
        response = self.client.post(url, data={'private_key': PRIVATE_KEY, 'user_keys': []}, **self.header)
        self.assertHttpStatus(response, status.HTTP_403_FORBIDDEN)

    def test_legacy_activate_user_key_empty_ids_guard(self):
        from netbox_secrets.api.views import LegacyActivateUserKeyViewSet

        factory = APIRequestFactory()
        request = factory.post('/api/plugins/secrets/activate-user-key/', data={})
        force_authenticate(request, user=self.user)

        with mock.patch('netbox_secrets.api.views.serializers.ActivateUserKeySerializer') as serializer_cls:
            serializer = serializer_cls.return_value
            serializer.is_valid.return_value = True
            serializer.validated_data = {'private_key': PRIVATE_KEY, 'user_key_ids': []}
            response = LegacyActivateUserKeyViewSet.as_view({'post': 'create'})(request)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_legacy_activate_user_key_empty_ids_direct(self):
        from netbox_secrets.api.views import LegacyActivateUserKeyViewSet

        class DummySerializer:
            def __init__(self, *args, **kwargs):
                self.validated_data = {'private_key': PRIVATE_KEY, 'user_key_ids': []}

            def is_valid(self):
                return True

        request = APIRequestFactory().post(
            '/api/plugins/secrets/activate-user-key/',
            data={},
            content_type='application/x-www-form-urlencoded',
        )
        force_authenticate(request, user=self.user)
        viewset = LegacyActivateUserKeyViewSet()
        drf_request = Request(request, parsers=[FormParser()])
        viewset.serializer_class = DummySerializer
        response = viewset.create(drf_request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
