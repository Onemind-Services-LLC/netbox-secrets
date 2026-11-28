from io import StringIO
from unittest import mock

from core.models import ObjectChange
from dcim.models import Device
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from extras.models import CustomField, ExportTemplate, JournalEntry, Tag
from users.models import ObjectPermission
from utilities.testing import TestCase, create_test_device

from netbox_secrets.models import Secret, SecretRole

APP_LABEL = 'netbox_secrets'


def run_command(*args, **kwargs):
    out = StringIO()
    call_command('netbox_secrets_uninstall', *args, stdout=out, **kwargs)
    return out.getvalue()


def plugin_tables():
    with connection.cursor() as cursor:
        return [t for t in connection.introspection.table_names(cursor) if t.startswith(f'{APP_LABEL}_')]


def plugin_functions():
    with connection.cursor() as cursor:
        cursor.execute("SELECT proname FROM pg_proc WHERE proname LIKE %s", [f'{APP_LABEL}%'])
        return [row[0] for row in cursor.fetchall()]


def migration_rows():
    with connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM django_migrations WHERE app = %s", [APP_LABEL])
        return cursor.fetchone()[0]


def ltree_installed():
    with connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM pg_extension WHERE extname = 'ltree'")
        return cursor.fetchone()[0] == 1


class UninstallCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.device = create_test_device('uninstall-device')
        cls.parent_role = SecretRole.objects.create(name='Parent', slug='parent')
        cls.role = SecretRole.objects.create(name='Child', slug='child', parent=cls.parent_role)
        secret = Secret(role=cls.role, name='password', assigned_object=cls.device)
        secret.ciphertext = b'x' * 40
        secret.hash = 'hash'
        secret.save()
        cls.secret = secret

    def setUp(self):
        super().setUp()
        self.secret_type = ContentType.objects.get_for_model(Secret)
        self.device_type = ContentType.objects.get_for_model(Device)

        # A change log entry and a journal entry that point at the plugin's content type
        ObjectChange.objects.create(
            changed_object_type=self.secret_type,
            changed_object_id=self.secret.pk,
            action='create',
            user_name='tester',
            request_id='00000000-0000-0000-0000-000000000001',
            object_repr='password',
            postchange_data={},
        )
        JournalEntry.objects.create(
            assigned_object_type=self.secret_type,
            assigned_object_id=self.secret.pk,
            comments='journal',
        )

        # Objects that only apply to the plugin's models...
        self.only_secret_field = CustomField.objects.create(name='only_secret', type='text')
        self.only_secret_field.object_types.set([self.secret_type])
        self.only_secret_template = ExportTemplate.objects.create(name='only_secret', template_code='x')
        self.only_secret_template.object_types.set([self.secret_type])
        self.only_secret_permission = ObjectPermission.objects.create(name='only_secret', actions=['view'])
        self.only_secret_permission.object_types.set([self.secret_type])

        # ...and one that is shared with a core model and must always survive
        self.shared_tag = Tag.objects.create(name='shared', slug='shared')
        self.shared_tag.object_types.set([self.secret_type, self.device_type])

    def assert_plugin_gone(self):
        self.assertEqual(plugin_tables(), [])
        self.assertEqual(plugin_functions(), [])
        self.assertEqual(migration_rows(), 0)
        self.assertFalse(ContentType.objects.filter(app_label=APP_LABEL).exists())
        self.assertFalse(Permission.objects.filter(content_type__app_label=APP_LABEL).exists())
        self.assertFalse(JournalEntry.objects.filter(comments='journal').exists())
        # The ltree extension is shared with NetBox core and must stay
        self.assertTrue(ltree_installed())

    def test_dry_run_changes_nothing(self):
        output = run_command('--dry-run')

        self.assertIn('Dry run', output)
        self.assertIn('netbox_secrets_secret', output)
        self.assertEqual(len(plugin_tables()), 4)
        self.assertTrue(Secret.objects.filter(pk=self.secret.pk).exists())
        self.assertEqual(ObjectChange.objects.filter(changed_object_type=self.secret_type).count(), 1)

    def test_wrong_confirmation_aborts(self):
        with mock.patch('builtins.input', return_value='no'):
            with self.assertRaises(CommandError):
                run_command()

        self.assertEqual(len(plugin_tables()), 4)
        self.assertTrue(Secret.objects.filter(pk=self.secret.pk).exists())

    def test_confirmation_prompt_accepts_the_keyword(self):
        with mock.patch('builtins.input', return_value='uninstall'):
            run_command()

        self.assert_plugin_gone()

    def test_uninstall_removes_everything_but_keeps_other_objects(self):
        self.assertEqual(len(plugin_tables()), 4)
        self.assertEqual(len(plugin_functions()), 2)

        run_command('--no-input')

        self.assert_plugin_gone()
        self.assertFalse(ObjectChange.objects.filter(object_repr='password').exists())

        # Shared objects are unlinked from the plugin but not deleted
        self.assertEqual(list(self.shared_tag.object_types.all()), [self.device_type])
        # Objects that applied only to the plugin are kept by default, with no object types left
        for obj in (self.only_secret_field, self.only_secret_template, self.only_secret_permission):
            obj.refresh_from_db()
            self.assertEqual(obj.object_types.count(), 0)

    def test_delete_orphans_removes_objects_that_only_applied_to_the_plugin(self):
        run_command('--no-input', '--delete-orphans')

        self.assert_plugin_gone()
        self.assertFalse(CustomField.objects.filter(pk=self.only_secret_field.pk).exists())
        self.assertFalse(ExportTemplate.objects.filter(pk=self.only_secret_template.pk).exists())
        self.assertFalse(ObjectPermission.objects.filter(pk=self.only_secret_permission.pk).exists())
        # Still shared with the device type, so it must survive
        self.assertTrue(Tag.objects.filter(pk=self.shared_tag.pk).exists())

    def test_running_twice_is_a_no_op(self):
        run_command('--no-input')
        output = run_command('--no-input')

        self.assertIn('Nothing to do', output)
        self.assert_plugin_gone()
