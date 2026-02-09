from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from netbox_secrets.filtersets import SecretFilterSet, SecretRoleFilterSet, UserKeyFilterSet
from netbox_secrets.models import Secret, SecretRole, UserKey
from netbox_secrets.tests.constants import PUBLIC_KEY
from utilities.testing import create_test_device


class UserKeyFilterSetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user1 = User.objects.create_user(username='alice')
        cls.user2 = User.objects.create_user(username='bob')
        UserKey.objects.create(user=cls.user1, public_key=PUBLIC_KEY)
        UserKey.objects.create(user=cls.user2, public_key=PUBLIC_KEY)

    def test_search_filter(self):
        qs = UserKey.objects.all()
        fs = UserKeyFilterSet(data={'q': 'ali'}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = UserKeyFilterSet(data={'q': ''}, queryset=qs)
        self.assertEqual(fs.qs.count(), 2)

    def test_user_filters(self):
        qs = UserKey.objects.all()
        fs = UserKeyFilterSet(data={'user_id': [self.user1.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = UserKeyFilterSet(data={'user': [self.user2.username]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

    def test_search_filter_blank_value(self):
        qs = UserKey.objects.all()
        fs = UserKeyFilterSet()
        self.assertEqual(fs.search(qs, 'q', '   ').count(), qs.count())


class SecretRoleFilterSetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.parent = SecretRole.objects.create(name='Parent', slug='parent')
        cls.child = SecretRole.objects.create(name='Child', slug='child', parent=cls.parent)

    def test_parent_filter(self):
        qs = SecretRole.objects.all()
        fs = SecretRoleFilterSet(data={'parent_id': [self.parent.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = SecretRoleFilterSet(data={'parent': [self.parent.slug]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

    def test_ancestor_filter(self):
        qs = SecretRole.objects.all()
        fs = SecretRoleFilterSet(data={'ancestor_id': [self.parent.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = SecretRoleFilterSet(data={'ancestor': [self.parent.slug]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)


class SecretFilterSetTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-filter')
        cls.secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(cls.device),
            assigned_object_id=cls.device.pk,
            role=cls.role,
            name='admin',
            description='device admin',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )

    def test_search_filter(self):
        qs = Secret.objects.all()
        fs = SecretFilterSet(data={'q': 'admin'}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = SecretFilterSet(data={'q': ''}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

    def test_role_filters(self):
        qs = Secret.objects.all()
        fs = SecretFilterSet(data={'role_id': [self.role.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = SecretFilterSet(data={'role': [self.role.slug]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

    def test_assigned_object_filters(self):
        qs = Secret.objects.all()
        ct = ContentType.objects.get_for_model(self.device)
        fs = SecretFilterSet(data={'assigned_object_type_id': [ct.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

        fs = SecretFilterSet(data={'assigned_object_id': [self.device.pk]}, queryset=qs)
        self.assertEqual(fs.qs.count(), 1)

    def test_search_filter_blank_value(self):
        qs = Secret.objects.all()
        fs = SecretFilterSet()
        self.assertEqual(fs.search(qs, 'q', '   ').count(), qs.count())
