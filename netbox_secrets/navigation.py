from extras.plugins import PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices

menu_items = (
    PluginMenuItem(
        link_text="User Key",
        link="plugins:netbox_secrets:userkey",
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
                color=ButtonColorChoices.GREEN,
                permissions=["netbox_secrets.add_secretrole"],
            ),
            PluginMenuButton(
                link="plugins:netbox_secrets:secretrole_import",
                title="Import Secret Role",
                icon_class="mdi mdi-upload",
                color=ButtonColorChoices.CYAN,
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
