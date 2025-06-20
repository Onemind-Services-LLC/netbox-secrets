from importlib.metadata import metadata

from netbox.plugins import PluginConfig

metadata = metadata('netbox_secrets')


class NetBoxSecrets(PluginConfig):
    name = metadata.get('Name').replace('-', '_')
    verbose_name = metadata.get('Name')
    description = metadata.get('Summary')
    version = metadata.get('Version')
    author = metadata.get('Author')
    author_email = metadata.get('Author-email')
    base_url = 'secrets'
    min_version = '4.3.0'
    max_version = '4.3.99'
    required_settings = []
    default_settings = {
        'apps': ['dcim.device', 'virtualization.virtualmachine'],
        'display_default': 'left_page',
        'display_setting': {},
        'public_key_size': 2048,
    }

    def ready(self):
        super().ready()
        from . import signals


config = NetBoxSecrets
