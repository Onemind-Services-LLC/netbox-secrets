from django.contrib.contenttypes.models import ContentType

from extras.plugins import PluginTemplateExtension
from .models import Secret


class Secrets(PluginTemplateExtension):

    def right_page(self):
        obj = self.context['object']

        secrets = None
        if ContentType.objects.get_for_model(obj).name == 'device':
            secrets = Secret.objects.filter(device=obj)
        elif ContentType.objects.get_for_model(obj).name == 'virtualmachine':
            secrets = Secret.objects.filter(virtualmachine=obj)

        return self.render('netbox_secretstore/inc/device_secrets.html', extra_context={
            'secrets': secrets,
        })


class DeviceSecrets(Secrets):
    model = 'dcim.device'


class VMSecrets(Secrets):
    model = 'virtualization.virtualmachine'


template_extensions = [DeviceSecrets, VMSecrets]
