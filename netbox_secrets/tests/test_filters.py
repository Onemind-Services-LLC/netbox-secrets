from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.test import TestCase
from virtualization.models import Cluster, ClusterType, VirtualMachine

from netbox_secrets.filtersets import *
from netbox_secrets.models import Secret, SecretRole


class SecretRoleTestCase(TestCase):
    queryset = SecretRole.objects.all()
    filterset = SecretRoleFilterSet

    @classmethod
    def setUpTestData(cls):
        roles = (
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
            SecretRole(name='Secret Role 3', slug='secret-role-3'),
        )
        SecretRole.objects.bulk_create(roles)

    def test_id(self):
        params = {'id': self.queryset.values_list('pk', flat=True)[:2]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_name(self):
        name = SecretRole.objects.all()
        params = {'name': [name[0].pk, name[1].pk]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_slug(self):
        params = {'slug': ['secret-role-1', 'secret-role-2']}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)


class SecretTestCase(TestCase):
    queryset = Secret.objects.all()
    filterset = SecretFilterSet

    @classmethod
    def setUpTestData(cls):
        site = Site.objects.create(name='Site 1', slug='site-1')
        manufacturer = Manufacturer.objects.create(name='Manufacturer 1', slug='manufacturer-1')
        device_type = DeviceType.objects.create(manufacturer=manufacturer, model='Device Type 1')
        device_role = DeviceRole.objects.create(name='Device Role 1', slug='device-role-1')

        devices = (
            Device(device_type=device_type, name='Device 1', site=site, device_role=device_role),
            Device(device_type=device_type, name='Device 2', site=site, device_role=device_role),
            Device(device_type=device_type, name='Device 3', site=site, device_role=device_role),
        )
        Device.objects.bulk_create(devices)

        cluster_type = ClusterType.objects.create(name='Cluster Type 1', slug='cluster-type-1')
        cluster = Cluster.objects.create(name='Cluster 1', type=cluster_type)
        virtual_machines = (
            VirtualMachine(name='Virtual Machine 1', cluster=cluster),
            VirtualMachine(name='Virtual Machine 2', cluster=cluster),
            VirtualMachine(name='Virtual Machine 3', cluster=cluster),
        )
        VirtualMachine.objects.bulk_create(virtual_machines)

        roles = (
            SecretRole(name='Secret Role 1', slug='secret-role-1'),
            SecretRole(name='Secret Role 2', slug='secret-role-2'),
            SecretRole(name='Secret Role 3', slug='secret-role-3'),
        )
        SecretRole.objects.bulk_create(roles)

        secrets = (
            Secret(assigned_object=devices[0], role=roles[0], name='Secret 1', plaintext='SECRET DATA'),
            Secret(assigned_object=devices[1], role=roles[1], name='Secret 2', plaintext='SECRET DATA'),
            Secret(assigned_object=devices[2], role=roles[2], name='Secret 3', plaintext='SECRET DATA'),
            Secret(assigned_object=virtual_machines[0], role=roles[0], name='Secret 4', plaintext='SECRET DATA'),
            Secret(assigned_object=virtual_machines[1], role=roles[1], name='Secret 5', plaintext='SECRET DATA'),
            Secret(assigned_object=virtual_machines[2], role=roles[2], name='Secret 6', plaintext='SECRET DATA'),
        )
        # Must call save() to encrypt Secrets
        for s in secrets:
            s.save()

    def test_id(self):
        params = {'id': self.queryset.values_list('pk', flat=True)[:2]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_name(self):
        name = Secret.objects.all()
        params = {'name': [name[0].pk, name[1].pk, name[2].pk, name[3].pk, name[4].pk, name[5].pk]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 6)

    def test_role(self):
        roles = SecretRole.objects.all()[:2]
        params = {'role_id': [roles[0].pk, roles[1].pk]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 4)
        params = {'role': [roles[0].slug, roles[1].slug]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 4)
