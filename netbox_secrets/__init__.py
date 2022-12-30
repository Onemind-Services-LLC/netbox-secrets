from extras.plugins import PluginConfig


from importlib.metadata import metadata

metadata = metadata('netbox_secrets')


class NetBoxSecrets(PluginConfig):
    name = metadata.get('Name').replace('-', '_')
    verbose_name = metadata.get('Summary')
    description = metadata.get('Description')
    version = metadata.get('Version')
    author = metadata.get('Author')
    author_email = metadata.get('Author-email')
    base_url = 'secrets'
    min_version = '3.3.0'
    max_version = '3.3.99'
    required_settings = []
    default_settings = {
        'public_key_size': 2048
    }


config = NetBoxSecrets
