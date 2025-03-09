from django.conf import settings

from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

plugins_settings = settings.PLUGINS_CONFIG.get('netbox_secrets')

menu_buttons = (
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

if plugins_settings.get('top_level_menu'):
    menu = PluginMenu(
        label='Secrets',
        groups=(('Secrets', menu_buttons),),
        icon_class='mdi mdi-eye-closed',
    )
else:
    menu_items = menu_buttons
