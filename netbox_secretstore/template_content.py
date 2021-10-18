from extras.plugins import PluginTemplateExtension
from .models import Secret


class Secrets(PluginTemplateExtension):

    def right_page(self):
        obj = self.context['object']
        return self.render('netbox_secretstore/inc/device_secrets.html', extra_context={
            'secrets': Secret.objects.filter(device=obj),
        })


class DeviceSecrets(Secrets):
    model = 'dcim.device'


class VMSecrets(Secrets):
    model = 'virtualization.virtualMachine'


template_extensions = [DeviceSecrets, VMSecrets]
