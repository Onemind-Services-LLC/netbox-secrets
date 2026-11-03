from django.contrib.contenttypes.models import ContentType

from core.models import ObjectType
from netbox_secrets.models import Secret, SecretRole
from users.models import ObjectPermission
from utilities.testing import TestCase, create_test_device


class SecretsPanelPermissionTestCase(TestCase):
    """
    The device/VM secrets panel must enforce object-level view permissions.

    Any user holding the global view_secret permission can see the panel, so the
    panel queryset has to be restricted like every other secret surface: a user
    whose view_secret grant is constrained to one role must not see the names or
    roles of secrets assigned to other roles.
    """

    user_permissions = ('dcim.view_device',)

    @classmethod
    def setUpTestData(cls):
        cls.device = create_test_device('panel-permissions')
        cls.role_a = SecretRole.objects.create(name='Role A', slug='role-a')
        cls.role_b = SecretRole.objects.create(name='Role B', slug='role-b')
        assigned_type = ContentType.objects.get_for_model(cls.device)
        for role in (cls.role_a, cls.role_b):
            Secret.objects.create(
                assigned_object_type=assigned_type,
                assigned_object_id=cls.device.pk,
                role=role,
                name=f'secret-{role.slug}',
                ciphertext=b'0123456789abcdef' * 5,
                hash='dummy',
            )
        cls.obj_perm = ObjectPermission(
            name='View Role A secrets',
            actions=['view'],
            constraints={'role__slug': cls.role_a.slug},
        )
        cls.obj_perm.save()
        cls.obj_perm.object_types.add(ObjectType.objects.get_for_model(Secret))

    def setUp(self):
        super().setUp()
        self.obj_perm.users.add(self.user)

    def test_constrained_user_sees_only_permitted_secrets(self):
        response = self.client.get(self.device.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'secret-role-a')
        self.assertNotContains(response, 'secret-role-b')

    def test_unrestricted_user_sees_all_secrets(self):
        self.add_permissions('netbox_secrets.view_secret')
        response = self.client.get(self.device.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertContains(response, 'secret-role-a')
        self.assertContains(response, 'secret-role-b')

    def test_user_without_view_permission_sees_no_panel(self):
        self.obj_perm.users.remove(self.user)
        response = self.client.get(self.device.get_absolute_url())
        self.assertHttpStatus(response, 200)
        self.assertNotContains(response, 'secret-role-a')
        self.assertNotContains(response, 'secret-role-b')
