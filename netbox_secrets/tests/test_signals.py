import sys
from unittest import mock

from django.db import ProgrammingError
from django.test import SimpleTestCase, override_settings

from netbox_secrets import signals


class ConfigureGenericRelationsTestCase(SimpleTestCase):
    def test_skip_during_tests(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'test']):
            with mock.patch('netbox_secrets.signals.apps.get_model') as get_model:
                signals.configure_generic_relations(sender=None)

        get_model.assert_not_called()

    @override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device']}})
    def test_add_generic_relation(self):
        class DummyModel:
            pass

        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.apps.get_model', return_value=DummyModel) as get_model:
                with mock.patch('netbox_secrets.signals.GenericRelation') as generic_relation:
                    signals.configure_generic_relations(sender=None)

        get_model.assert_called_once_with('dcim', 'device')
        generic_relation.assert_called_once_with(
            to='netbox_secrets.Secret',
            content_type_field='assigned_object_type',
            object_id_field='assigned_object_id',
            related_query_name='device',
        )
        generic_relation.return_value.contribute_to_class.assert_called_once_with(DummyModel, 'secrets')

    @override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['invalid-entry']}})
    def test_skip_invalid_model_path(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.apps.get_model') as get_model:
                signals.configure_generic_relations(sender=None)

        get_model.assert_not_called()

    @override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device']}})
    def test_skip_missing_model_class(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.apps.get_model', return_value=None) as get_model:
                with mock.patch('netbox_secrets.signals.GenericRelation') as generic_relation:
                    signals.configure_generic_relations(sender=None)

        get_model.assert_called_once_with('dcim', 'device')
        generic_relation.assert_not_called()

    @override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device']}})
    def test_skip_model_with_existing_secrets_relation(self):
        class DummyModel:
            secrets = object()

        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.apps.get_model', return_value=DummyModel) as get_model:
                with mock.patch('netbox_secrets.signals.GenericRelation') as generic_relation:
                    signals.configure_generic_relations(sender=None)

        get_model.assert_called_once_with('dcim', 'device')
        generic_relation.assert_not_called()

    @override_settings(PLUGINS_CONFIG={'netbox_secrets': {'apps': ['dcim.device']}})
    def test_programming_error(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.apps.get_model', side_effect=ProgrammingError):
                signals.configure_generic_relations(sender=None)
