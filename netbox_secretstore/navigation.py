from extras.plugins import PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices

menu_items = (
    PluginMenuItem(
        link='plugins:netbox_secretstore:userkey',
        link_text='User Key',
        buttons=()
    ),
    PluginMenuItem(
        link='plugins:netbox_secretstore:secretrole_list',
        link_text='Secret Roles',
        buttons=(
            PluginMenuButton('plugins:netbox_secretstore:secretrole_add', 'Add', 'mdi mdi-plus-thick', ButtonColorChoices.GREEN),
            PluginMenuButton('plugins:netbox_secretstore:secretrole_import', 'Import', 'mdi mdi-database-import-outline', ButtonColorChoices.BLUE),
        )
    ),
    PluginMenuItem(
        link='plugins:netbox_secretstore:secret_list',
        link_text='Secrets',
        buttons=(
            PluginMenuButton('plugins:netbox_secretstore:secret_add', 'Add', 'mdi mdi-plus-thick', ButtonColorChoices.GREEN),
            PluginMenuButton('plugins:netbox_secretstore:secret_import', 'Import', 'mdi mdi-database-import-outline', ButtonColorChoices.BLUE),
        )
    ),
)