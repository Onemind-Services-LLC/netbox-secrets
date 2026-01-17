from django.conf import settings

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

plugins_settings = settings.PLUGINS_CONFIG.get('netbox_secrets')

# Legacy secrets menu items
legacy_secrets_buttons = (
    PluginMenuItem(
        link_text="User Keys",
        link="plugins:netbox_secrets:userkey_list",
        permissions=["netbox_secrets.view_userkey"],
    ),
    PluginMenuItem(
        link_text="Secret Roles",
        link="plugins:netbox_secrets:secretrole_list",
        permissions=["netbox_secrets.view_secretrole"],
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_secrets:secretrole_add",
                title="Add Secret Role",
                icon_class="mdi mdi-plus-thick",
                permissions=["netbox_secrets.add_secretrole"],
            ),
            PluginMenuButton(
                link="plugins:netbox_secrets:secretrole_bulk_import",
                title="Import Secret Role",
                icon_class="mdi mdi-upload",
                permissions=["netbox_secrets.add_secretrole"],
            ),
        ),
    ),
    PluginMenuItem(
        link_text="Secrets",
        link="plugins:netbox_secrets:secret_list",
        permissions=["netbox_secrets.view_secret"],
    ),
)

# Tenant crypto menu items (zero-knowledge secret sharing)
tenant_crypto_buttons = (
    PluginMenuItem(
        link_text="Tenant Secrets",
        link="plugins:netbox_secrets:tenantsecret_list",
        permissions=["netbox_secrets.view_tenantsecret"],
    ),
    PluginMenuItem(
        link_text="My Memberships",
        link="plugins:netbox_secrets:tenantmembership_list",
        permissions=["netbox_secrets.view_tenantmembership"],
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_secrets:tenant_crypto_setup",
                title="Setup Passkey",
                icon_class="mdi mdi-key-plus",
                permissions=["netbox_secrets.add_tenantmembership"],
            ),
        ),
    ),
    PluginMenuItem(
        link_text="Service Accounts",
        link="plugins:netbox_secrets:tenantserviceaccount_list",
        permissions=["netbox_secrets.view_tenantserviceaccount"],
    ),
)

if plugins_settings.get('top_level_menu'):
    menu = PluginMenu(
        label='Secrets',
        groups=(
            ('Legacy Secrets', legacy_secrets_buttons),
            ('Tenant Crypto', tenant_crypto_buttons),
        ),
        icon_class='mdi mdi-eye-closed',
    )
else:
    menu_items = legacy_secrets_buttons + tenant_crypto_buttons
