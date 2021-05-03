from extras.plugins import PluginConfig

class NetBoxSecretStore(PluginConfig):
    name = 'netbox_secretstore'
    verbose_name = 'Netbox Secret Store'
    description = 'A Secret Storage for NetBox'
    version = '0.1'
    author = 'NetBox Maintainers'
    author_email = ''
    base_url = 'secretstore'
    min_version = '2.11.0'
    required_settings = []
    caching_config = {
        '*': {
            'ops': 'all'
        }
    }
    default_settings = {
        'loud': False
    }

config = NetBoxSecretStore