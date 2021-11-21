from django.contrib.contenttypes.models import ContentType

from extras.plugins import PluginTemplateExtension
from .models import Secret


class Secrets(PluginTemplateExtension):

    def right_page(self):
        obj = self.context['object']

        secrets = None
        ctype = ContentType.objects.get_for_model(obj)
        if ctype.model == 'device':
            secrets = Secret.objects.filter(assigned_object_id=obj.pk, assigned_object_type=ctype)
        elif ctype.model == 'virtualmachine':
            secrets = Secret.objects.filter(assigned_object_id=obj.pk, assigned_object_type=ctype)

        return self.render('netbox_secretstore/inc/device_secrets.html', extra_context={
            'secrets': secrets,
            'type': ctype.model if ctype.model == 'device' else ctype.name.replace(' ', '_'),
        })


class DeviceSecrets(Secrets):
    model = 'dcim.device'


class VMSecrets(Secrets):
    model = 'virtualization.virtualmachine'


template_extensions = [DeviceSecrets, VMSecrets]
