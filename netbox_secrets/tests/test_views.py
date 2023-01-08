from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey
from utilities.testing import ViewTestCases
from .constants import PRIVATE_KEY, PUBLIC_KEY


class SecretsTestMixin:
    def _get_base_url(self):
        """
        Return the base format for a URL for the test's model. Override this to test for a model which belongs
        to a different app (e.g. testing Interfaces within the virtualization app).
        """
        return '{}:{}:{}_{{}}'.format(
            'plugins',
            self.model._meta.app_label,
            self.model._meta.model_name
        )


class SecretRoleTestCase(
    SecretsTestMixin,
    ViewTestCases.GetObjectViewTestCase,
    ViewTestCases.GetObjectChangelogViewTestCase,
    ViewTestCases.DeleteObjectViewTestCase,
    ViewTestCases.ListObjectsViewTestCase,
    ViewTestCases.BulkEditObjectsViewTestCase,
    ViewTestCases.BulkDeleteObjectsViewTestCase
):
    model = SecretRole

    @classmethod
    def setUpTestData(cls):
        SecretRole.objects.bulk_create([
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
            SecretRole(name='Secret Role 3', slug='secret-role-3'),
        ])

        cls.form_data = {
            'name': 'Secret Role X',
            'slug': 'secret-role-x',
            'description': 'A secret role',
        }

        cls.csv_data = (
            "name,slug",
            "Secret Role 4,secret-role-4",
            "Secret Role 5,secret-role-5",
            "Secret Role 6,secret-role-6",
        )

        cls.bulk_edit_data = {
            'description': 'New description',
        }


# TODO: Change base class to PrimaryObjectViewTestCase
class SecretTestCase(
    SecretsTestMixin,
    ViewTestCases.GetObjectViewTestCase,
    ViewTestCases.GetObjectChangelogViewTestCase,
    ViewTestCases.DeleteObjectViewTestCase,
    ViewTestCases.ListObjectsViewTestCase,
    ViewTestCases.BulkDeleteObjectsViewTestCase
):
    model = Secret

    @classmethod
    def setUpTestData(cls):
        site = Site.objects.create(name='Site 1', slug='site-1')
        manufacturer = Manufacturer.objects.create(name='Manufacturer 1', slug='manufacturer-1')
        devicetype = DeviceType.objects.create(manufacturer=manufacturer, model='Device Type 1')
        devicerole = DeviceRole.objects.create(name='Device Role 1', slug='device-role-1')

        devices = (
            Device(name='Device 1', site=site, device_type=devicetype, device_role=devicerole),
            Device(name='Device 2', site=site, device_type=devicetype, device_role=devicerole),
            Device(name='Device 3', site=site, device_type=devicetype, device_role=devicerole),
        )
        Device.objects.bulk_create(devices)

        secretroles = (
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
        )
        SecretRole.objects.bulk_create(secretroles)

        # Create one secret per device to allow bulk-editing of names (which must be unique per device/role)
        Secret.objects.bulk_create((
            Secret(assigned_object=devices[0], role=secretroles[0], name='Secret 1', ciphertext=b'1234567890'),
            Secret(assigned_object=devices[1], role=secretroles[0], name='Secret 2', ciphertext=b'1234567890'),
            Secret(assigned_object=devices[2], role=secretroles[0], name='Secret 3', ciphertext=b'1234567890'),
        ))

        cls.form_data = {
            'assigned_object_type': 'dcim.device',
            'assigned_object_id': devices[1].pk,
            'role': secretroles[1].pk,
            'name': 'Secret X',
        }

    def setUp(self):
        super().setUp()

        # Set up a master key for the test user
        userkey = UserKey(user=self.user, public_key=PUBLIC_KEY)
        userkey.save()
        master_key = userkey.get_master_key(PRIVATE_KEY)
        self.session_key = SessionKey(userkey=userkey)
        self.session_key.save(master_key)
