import sys
from unittest import mock

from django.db import ProgrammingError
from django.test import TestCase

from netbox_secrets import signals


class ConfigureGenericRelationsTestCase(TestCase):
    def test_skip_during_tests(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'test']):
            with mock.patch('netbox_secrets.signals.ContentType.objects.filter') as filter_ct:
                signals.configure_generic_relations(sender=None)
                filter_ct.assert_not_called()

    def test_add_generic_relation(self):
        class DummyModel:
            pass

        dummy_ct = mock.Mock()
        dummy_ct.model_class.return_value = DummyModel
        dummy_ct.model = 'dummy'

        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.ContentType.objects.filter', return_value=[dummy_ct]):
                with mock.patch('netbox_secrets.signals.GenericRelation.contribute_to_class') as contribute:
                    signals.configure_generic_relations(sender=None)
                    contribute.assert_called()

    def test_model_class_none(self):
        dummy_ct = mock.Mock()
        dummy_ct.model_class.return_value = None
        dummy_ct.model = 'dummy'
        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.ContentType.objects.filter', return_value=[dummy_ct]):
                signals.configure_generic_relations(sender=None)

    def test_programming_error(self):
        with mock.patch.object(sys, 'argv', ['manage.py', 'runserver']):
            with mock.patch('netbox_secrets.signals.ContentType.objects.filter', side_effect=ProgrammingError):
                signals.configure_generic_relations(sender=None)
