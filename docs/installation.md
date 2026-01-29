# Installation

## Requirements

- A supported NetBox installation
- Python environment with access to NetBox dependencies
- Database already configured for NetBox

## Install from PyPI

```shell
pip install netbox-secrets
```

## Install from Source (development)

```shell
git clone <your-fork-or-repo-url>
cd netbox-secrets
pip install -e .
```

## Enable the Plugin

Add the plugin to NetBox configuration:

```python
# configuration.py
PLUGINS = [
    'netbox_secrets',
]
```

## Run Migrations and Collect Static Files

```shell
./manage.py migrate
./manage.py collectstatic --no-input
```

## Upgrade

1) Upgrade the package

```shell
pip install --upgrade netbox-secrets
```

2) Run migrations and collectstatic again

```shell
./manage.py migrate
./manage.py collectstatic --no-input
```

## Uninstall

1) Remove the plugin from `PLUGINS` in `configuration.py`
2) Uninstall the package: `pip uninstall netbox-secrets`
