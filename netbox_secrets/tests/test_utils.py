import base64
import importlib
from unittest import mock

from django.contrib.contenttypes.models import ContentType
from django.db.utils import OperationalError
from django.test import RequestFactory, TestCase, override_settings

from netbox_secrets import constants as plugin_constants
from netbox_secrets.hashers import SecretValidationHasher
from netbox_secrets.models import Secret, SecretRole
from netbox_secrets.tests.constants import PRIVATE_KEY, PUBLIC_KEY
from netbox_secrets.utils import decrypt_master_key, encrypt_master_key, generate_random_key, get_session_key
from utilities.testing import create_test_device


class CryptoHelpersTestCase(TestCase):
    def test_generate_random_key_valid(self):
        key = generate_random_key(bits=256)
        self.assertEqual(len(key), 32)

    def test_generate_random_key_invalid(self):
        with self.assertRaises(Exception):
            generate_random_key(bits=255)

    def test_encrypt_decrypt_master_key(self):
        master_key = generate_random_key()
        cipher = encrypt_master_key(master_key, PUBLIC_KEY)
        self.assertEqual(decrypt_master_key(cipher, PRIVATE_KEY), master_key)


class RequestHelperTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.session_key = base64.b64encode(b'secret-session-key').decode('utf-8')

    def test_get_session_key_from_cookie(self):
        request = self.factory.get('/')
        request.COOKIES['netbox_secrets_sessionid'] = self.session_key
        self.assertEqual(get_session_key(request), b'secret-session-key')

    def test_get_session_key_from_header(self):
        request = self.factory.get('/', HTTP_X_SESSION_KEY=self.session_key)
        self.assertEqual(get_session_key(request), b'secret-session-key')

    def test_get_session_key_from_post(self):
        request = self.factory.post('/', data={'session_key': self.session_key})
        self.assertEqual(get_session_key(request), b'secret-session-key')

    def test_get_session_key_invalid(self):
        request = self.factory.get('/', HTTP_X_SESSION_KEY='not-base64')
        self.assertIsNone(get_session_key(request))

    def test_get_session_key_missing(self):
        request = self.factory.get('/')
        self.assertIsNone(get_session_key(request))


class ConstantsTestCase(TestCase):
    def test_get_assignable_models_filter(self):
        with mock.patch.object(plugin_constants, '_plugin_settings', {'apps': ['dcim.device', 'bad.entry']}):
            q = plugin_constants.get_assignable_models_filter()
            ct = ContentType.objects.get(app_label='dcim', model='device')
            self.assertTrue(ContentType.objects.filter(q, pk=ct.pk).exists())

    def test_get_assignable_models_filter_malformed(self):
        with mock.patch.object(plugin_constants, '_plugin_settings', {'apps': ['invalid']}):
            q = plugin_constants.get_assignable_models_filter()
            self.assertEqual(q.children, [])

    def test_assignable_models_filter_empty(self):
        with mock.patch.object(plugin_constants, '_plugin_settings', {'apps': []}):
            q = plugin_constants.get_assignable_models_filter()
            self.assertEqual(q.children, [])


class HashersTestCase(TestCase):
    def test_secret_validation_hasher_iterations(self):
        self.assertEqual(SecretValidationHasher.iterations, 1000)

    def test_utils_secret_validation_hasher_iterations(self):
        from netbox_secrets.utils.hashers import SecretValidationHasher as UtilsHasher

        self.assertEqual(UtilsHasher.iterations, 1000)


class NavigationTestCase(TestCase):
    def test_top_level_menu_enabled(self):
        with override_settings(PLUGINS_CONFIG={'netbox_secrets': {'top_level_menu': True}}):
            nav = importlib.import_module('netbox_secrets.navigation')
            for attr in ('menu', 'menu_items'):
                if hasattr(nav, attr):
                    delattr(nav, attr)
            nav = importlib.reload(nav)
            self.assertTrue(hasattr(nav, 'menu'))
            self.assertFalse(hasattr(nav, 'menu_items'))

    def test_top_level_menu_disabled(self):
        with override_settings(PLUGINS_CONFIG={'netbox_secrets': {'top_level_menu': False}}):
            nav = importlib.import_module('netbox_secrets.navigation')
            for attr in ('menu', 'menu_items'):
                if hasattr(nav, attr):
                    delattr(nav, attr)
            nav = importlib.reload(nav)
            self.assertFalse(hasattr(nav, 'menu'))
            self.assertTrue(hasattr(nav, 'menu_items'))


class TemplateContentTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.role = SecretRole.objects.create(name='Role', slug='role')
        cls.device = create_test_device('device-template')
        cls.secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(cls.device),
            assigned_object_id=cls.device.pk,
            role=cls.role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )

    def test_get_display_on(self):
        template_content = importlib.import_module('netbox_secrets.template_content')
        with mock.patch.object(template_content, 'plugin_settings', {'display_default': 'tab_view'}):
            self.assertEqual(template_content.get_display_on('dcim.device'), 'tab_view')
        with mock.patch.object(template_content, 'plugin_settings', {'display_setting': {'dcim.device': 'left'}}):
            self.assertEqual(template_content.get_display_on('dcim.device'), 'left')

    def test_secrets_panel(self):
        template_content = importlib.import_module('netbox_secrets.template_content')

        class Dummy:
            def __init__(self, obj):
                self.context = {'object': obj}
                self.models = ['dcim.device']
                self.rendered = None

            def render(self, template, extra_context=None):
                self.rendered = (template, extra_context)
                return 'rendered'

        dummy = Dummy(self.device)
        with mock.patch.object(template_content, 'plugin_settings', {'apps': ['dcim.device']}):
            result = template_content.secrets_panel(dummy)
            self.assertEqual(result, 'rendered')
            self.assertIn('secrets', dummy.rendered[1])

        dummy.models = []
        self.assertIsNone(template_content.secrets_panel(dummy))

    def test_tab_view_registers(self):
        template_content = importlib.import_module('netbox_secrets.template_content')
        captured = {}

        def fake_register_model_view(*args, **kwargs):
            def decorator(cls):
                captured['cls'] = cls
                return cls

            return decorator

        with mock.patch.object(template_content, 'register_model_view', side_effect=fake_register_model_view):
            template_content.tab_view(self.device.__class__)
            self.assertIn('cls', captured)

        view = captured['cls']()
        request = RequestFactory().get('/')
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.create_user(username='superuser')
        user.is_superuser = True
        user.is_staff = True
        user.save()
        request.user = user
        children = view.get_children(request, self.device)
        self.assertIn(self.secret, list(children))

    def test_secret_add_button(self):
        template_content = importlib.import_module('netbox_secrets.template_content')
        Button = template_content.secret_add_button('dcim.device')
        button = Button(context={'object': self.device})
        with mock.patch.object(button, 'render', return_value='ok') as render:
            self.assertEqual(button.buttons(), 'ok')
            render.assert_called_once()

    def test_template_content_operational_error(self):
        with override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device']}}):
            with mock.patch(
                'netbox_secrets.template_content.ContentType.objects.get', side_effect=OperationalError
            ), mock.patch('netbox_secrets.template_content.logger.warning'):
                importlib.reload(importlib.import_module('netbox_secrets.template_content'))

    def test_template_content_tab_view_branch(self):
        with override_settings(
            PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device'], 'display_default': 'tab_view'}}
        ):
            with mock.patch('utilities.views.register_model_view', return_value=lambda cls: cls):
                importlib.reload(importlib.import_module('netbox_secrets.template_content'))

    def test_template_content_unexpected_error(self):
        template_content = importlib.import_module('netbox_secrets.template_content')
        with override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['bad']}}):
            with self.assertRaises(Exception):
                importlib.reload(template_content)
        importlib.reload(template_content)


class GraphQLImportsTestCase(TestCase):
    def test_graphql_modules_import(self):
        importlib.import_module('netbox_secrets.graphql.filters')
        importlib.import_module('netbox_secrets.graphql.types')
        importlib.import_module('netbox_secrets.urls')


class TablesTestCase(TestCase):
    def test_tables_instantiate(self):
        from netbox_secrets.tables import SecretRoleTable, SecretTable, UserKeyTable

        role = SecretRole.objects.create(name='Role2', slug='role2')
        device = create_test_device('device-table')
        secret = Secret.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(device),
            assigned_object_id=device.pk,
            role=role,
            name='secret',
            ciphertext=b'0123456789abcdef' * 5,
            hash='dummy',
        )
        SecretRoleTable(SecretRole.objects.all())
        SecretTable(Secret.objects.all())
        from django.contrib.auth import get_user_model

        user_obj = get_user_model().objects.create_user(username='table-user')
        from netbox_secrets.models import UserKey

        UserKey.objects.create(user=user_obj, public_key=PUBLIC_KEY)
        UserKeyTable(UserKey.objects.all())
