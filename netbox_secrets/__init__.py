from importlib.metadata import metadata

from extras.plugins import PluginConfig

metadata = metadata('netbox_secrets')


class NetBoxSecrets(PluginConfig):
    name = metadata.get('Name').replace('-', '_')
    verbose_name = metadata.get('Summary')
    description = metadata.get('Description')
    version = metadata.get('Version')
    author = metadata.get('Author')
    author_email = metadata.get('Author-email')
    base_url = 'secrets'
    min_version = '3.4.0'
    max_version = '3.4.99'
    required_settings = []
    default_settings = {
        'apps': ['dcim.device', 'virtualization.virtualmachine'],
        'display_default': 'left_page',
        'display_setting': {},
        'enable_contacts': False,
        'public_key_size': 2048,
    }


config = NetBoxSecrets
