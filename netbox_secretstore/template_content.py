from extras.plugins import PluginTemplateExtension
from .models import Secret

class DeviceSecrets(PluginTemplateExtension):
    model = 'dcim.device'

    def right_page(self):
        obj = self.context['object']
        return self.render('netbox_secretstore/inc/device_secrets.html', extra_context={
            'secrets': Secret.objects.filter(device=obj),
        })

template_extensions = [DeviceSecrets]