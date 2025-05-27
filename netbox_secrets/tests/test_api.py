import base64

from django.urls import reverse
from rest_framework import status

from core.models import ObjectType
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from users.models import ObjectPermission
from utilities.testing import APITestCase, APIViewTestCases
from .constants import *
from ..models import *


class SecretsTestMixin:
    view_namespace = 'plugins-api:netbox_secrets'

    # Skip GraphQL tests for now
    def test_graphql_get_object(self):
        pass

    # Skip GraphQL tests for now
    def test_graphql_list_objects(self):
        pass


class AppTest(APITestCase):
    def test_root(self):
        url = reverse('plugins-api:netbox_secrets-api:api-root')
        response = self.client.get(f'{url}?format=api', **self.header)

        self.assertEqual(response.status_code, 200)


class SecretRoleTest(APIViewTestCases.APIViewTestCase):
    model = SecretRole
    view_namespace = 'plugins-api:netbox_secrets'
    brief_fields = ['display', 'id', 'name', 'secret_count', 'slug', 'url']

    @classmethod
    def setUpTestData(cls):
        secret_roles = (
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
            SecretRole(name='Secret Role 3', slug='secret-role-3'),
        )
        SecretRole.objects.bulk_create(secret_roles)

        cls.create_data = [
            {
                'name': 'Secret Role 4',
                'slug': 'secret-role-4',
            },
            {
                'name': 'Secret Role 5',
                'slug': 'secret-role-5',
            },
            {
                'name': 'Secret Role 6',
                'slug': 'secret-role-6',
            },
        ]


class SecretTest(APIViewTestCases.APIViewTestCase):
    model = Secret
    view_namespace = 'plugins-api:netbox_secrets'
    brief_fields = ['display', 'id', 'name', 'url']

    def setUp(self):
        super().setUp()

        # Create a UserKey for the test user
        userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
        userkey.save()

        # Create a SessionKey for the user
        self.master_key = userkey.get_master_key(PRIVATE_KEY)
        session_key = SessionKey(userkey=userkey)
        session_key.save(self.master_key)

        # Append the session key to the test client's request header
        self.header['HTTP_X_SESSION_KEY'] = base64.b64encode(session_key.key)

        site = Site.objects.create(name='Site 1', slug='site-1')
        manufacturer = Manufacturer.objects.create(name='Manufacturer 1', slug='manufacturer-1')
        devicetype = DeviceType.objects.create(manufacturer=manufacturer, model='Device Type 1')
        devicerole = DeviceRole.objects.create(name='Device Role 1', slug='device-role-1')
        device = Device.objects.create(name='Device 1', site=site, device_type=devicetype, role=devicerole)

        secret_roles = (
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
        )
        SecretRole.objects.bulk_create(secret_roles)

        secrets = (
            Secret(assigned_object=device, role=secret_roles[0], name='Secret 1', plaintext='ABC'),
            Secret(assigned_object=device, role=secret_roles[0], name='Secret 2', plaintext='DEF'),
            Secret(assigned_object=device, role=secret_roles[0], name='Secret 3', plaintext='GHI'),
        )
        for secret in secrets:
            secret.encrypt(self.master_key)
            secret.save()

        self.create_data = [
            {
                'assigned_object_type': 'dcim.device',
                'assigned_object_id': device.pk,
                'role': secret_roles[1].pk,
                'name': 'Secret 4',
                'plaintext': 'JKL',
            },
            {
                'assigned_object_type': 'dcim.device',
                'assigned_object_id': device.pk,
                'role': secret_roles[1].pk,
                'name': 'Secret 5',
                'plaintext': 'MNO',
            },
            {
                'assigned_object_type': 'dcim.device',
                'assigned_object_id': device.pk,
                'role': secret_roles[1].pk,
                'name': 'Secret 6',
                'plaintext': 'PQR',
            },
        ]

        self.bulk_update_data = {
            'role': secret_roles[1].pk,
        }

    def prepare_instance(self, instance):
        # Unlock the plaintext prior to evaluation of the instance
        instance.decrypt(self.master_key)
        return instance


class SessionKeyTest(
    APIViewTestCases.GetObjectViewTestCase,
    APIViewTestCases.ListObjectsViewTestCase,
    APIViewTestCases.DeleteObjectViewTestCase,
):
    model = SessionKey
    view_namespace = 'plugins-api:netbox_secrets'
    brief_fields = ['display', 'id', 'url']
    create_data = [
        {'private_key': PRIVATE_KEY},
        {'private_key': PRIVATE_KEY, 'preserve_key': True},
    ]

    def setUp(self):
        super().setUp()

        userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
        userkey.save()

        master_key = userkey.get_master_key(PRIVATE_KEY)
        self.session_key = SessionKey(userkey=userkey)
        self.session_key.save(master_key)

        self.header = {
            'HTTP_AUTHORIZATION': f'Token {self.token.key}',
        }

    def test_create_session_key(self):
        encoded_session_key = base64.b64encode(self.session_key.key).decode()

        # Add object-level permission
        obj_perm = ObjectPermission(name='Test permission', actions=['add'])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ObjectType.objects.get_for_model(self.model))
        initial_count = self._get_queryset().count()
        response = self.client.post(self._get_list_url(), self.create_data[0], format='json', **self.header)

        self.assertHttpStatus(response, status.HTTP_201_CREATED)
        self.assertEqual(self._get_queryset().count(), initial_count)

        self.assertIsNotNone(response.data.get('session_key'))
        self.assertNotEqual(response.data.get('session_key'), encoded_session_key)

    def test_get_session_key_preserved(self):
        encoded_session_key = base64.b64encode(self.session_key.key).decode()

        # Add object-level permission
        obj_perm = ObjectPermission(name='Test permission', actions=['add'])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ObjectType.objects.get_for_model(self.model))
        initial_count = self._get_queryset().count()
        response = self.client.post(self._get_list_url(), self.create_data[1], format='json', **self.header)

        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(self._get_queryset().count(), initial_count)

        self.assertIsNotNone(response.data.get('session_key'))
        self.assertEqual(response.data.get('session_key'), encoded_session_key)

    def test_get_object(self):
        instance = self._get_queryset().first()

        # Add object-level permission
        obj_perm = ObjectPermission(name='Test permission', constraints={'pk': instance.pk}, actions=['view'])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ObjectType.objects.get_for_model(self.model))

        # Try GET to permitted object
        url = self._get_detail_url(instance)
        self.assertHttpStatus(self.client.get(url, **self.header), status.HTTP_200_OK)

    def test_list_objects(self):
        instance = self._get_queryset().first()

        # Add object-level permission
        obj_perm = ObjectPermission(name='Test permission', constraints={'pk__in': [instance.pk]}, actions=['view'])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ObjectType.objects.get_for_model(self.model))

        # Try GET to permitted objects
        response = self.client.get(self._get_list_url(), **self.header)
        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_bulk_delete_objects(self):
        # Add object-level permission
        obj_perm = ObjectPermission(name='Test permission', actions=['delete'])
        obj_perm.save()
        obj_perm.users.add(self.user)
        obj_perm.object_types.add(ObjectType.objects.get_for_model(self.model))

        # Target the three most recently created objects to avoid triggering recursive deletions
        # (e.g. with MPTT objects)
        id_list = list(self._get_queryset().order_by('-id').values_list('id', flat=True)[:3])
        self.assertEqual(len(id_list), 1, "Insufficient number of objects to test bulk deletion")
        data = [{"id": id} for id in id_list]

        initial_count = self._get_queryset().count()
        response = self.client.delete(self._get_list_url(), data, format='json', **self.header)
        self.assertHttpStatus(response, status.HTTP_204_NO_CONTENT)
        self.assertEqual(self._get_queryset().count(), initial_count - 1)


class GetSessionKeyTest(APITestCase):
    def setUp(self):
        super().setUp()

        userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
        userkey.save()
        master_key = userkey.get_master_key(PRIVATE_KEY)
        self.session_key = SessionKey(userkey=userkey)
        self.session_key.save(master_key)

        self.header = {
            'HTTP_AUTHORIZATION': f'Token {self.token.key}',
        }

    def test_get_session_key(self):
        encoded_session_key = base64.b64encode(self.session_key.key).decode()

        url = reverse('plugins-api:netbox_secrets-api:get-session-key-list')
        data = {
            'private_key': PRIVATE_KEY,
        }
        response = self.client.post(url, data, **self.header)

        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertIsNotNone(response.data.get('session_key'))
        self.assertNotEqual(response.data.get('session_key'), encoded_session_key)

    def test_get_session_key_preserved(self):
        encoded_session_key = base64.b64encode(self.session_key.key).decode()

        url = reverse('plugins-api:netbox_secrets-api:get-session-key-list')
        data = {
            'private_key': PRIVATE_KEY,
            'preserve_key': True,
        }
        response = self.client.post(url, data, **self.header)

        self.assertHttpStatus(response, status.HTTP_200_OK)
        self.assertEqual(response.data.get('session_key'), encoded_session_key)
