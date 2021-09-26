from extras.plugins import PluginConfig


class NetBoxSecretStore(PluginConfig):
    name = 'netbox_secretstore'
    verbose_name = 'Netbox Secret Store'
    description = 'A Secret Storage for NetBox'
    version = '1.0.6'
    author = 'NetBox Maintainers'
    author_email = ''
    base_url = 'netbox_secretstore'
    min_version = '3.0.0'
    required_settings = []
    caching_config = {
        '*': {
            'ops': 'all'
        }
    }
    default_settings = {
        'public_key_size': 2048
    }


config = NetBoxSecretStore
