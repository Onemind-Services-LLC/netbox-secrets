from django.conf import settings

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

# Plugin configuration
_config = settings.PLUGINS_CONFIG.get("netbox_secrets", {})

# Menu item definitions
_MENU_ITEMS = (
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

# Export menu structure based on configuration
if _config.get("top_level_menu"):
    menu = PluginMenu(
        label="Secrets",
        groups=(("Secrets", _MENU_ITEMS),),
        icon_class="mdi mdi-eye-closed",
    )
else:
    menu_items = _MENU_ITEMS
