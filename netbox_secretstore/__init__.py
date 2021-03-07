from extras.plugins import PluginConfig

class NetBoxSecretStore(PluginConfig):
    name = 'netbox_secretstore'
    verbose_name = 'Netbox Secret Store'
    description = 'A Secret Storage for NetBox'
    version = '0.1'
    author = 'NetBox Maintainers'
    author_email = ''
    base_url = 'secretstore'
    required_settings = []
    default_settings = {
        'loud': False
    }

config = NetBoxSecretStore