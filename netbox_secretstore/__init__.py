from extras.plugins import PluginConfig


try:
    from importlib.metadata import metadata
except ModuleNotFoundError:
    from importlib_metadata import metadata

metadata = metadata('netbox_secretstore')


class NetBoxSecretStore(PluginConfig):
    name = metadata.get('Name').replace('-', '_')
    verbose_name = metadata.get('Summary')
    description = metadata.get('Description')
    version = metadata.get('Version')
    author = metadata.get('Author')
    author_email = metadata.get('Author-email')
    base_url = 'netbox_secretstore'
    min_version = '3.2.0'
    max_version = '3.3.0beta1'
    required_settings = []
    default_settings = {
        'public_key_size': 2048
    }


config = NetBoxSecretStore
