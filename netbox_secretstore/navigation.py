from extras.plugins import PluginMenuItem, PluginMenuButton

menu_items = (
    PluginMenuItem(link_text="User Key", link="plugins:netbox_secretstore:userkey"),
    PluginMenuItem(
        link_text="Secret Roles",
        link="plugins:netbox_secretstore:secretrole_list",
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_secretstore:secretrole_add",
                title="Add Secret Role",
                icon_class="mdi mdi-plus-thick",
                color="green",
            ),
            PluginMenuButton(
                link="plugins:netbox_secretstore:secretrole_import",
                title="Import Secret Role",
                icon_class="mdi mdi-upload",
                color="teal",
            ),
        ),
    ),
    PluginMenuItem(
        link_text="Secrets",
        link="plugins:netbox_secretstore:secret_list",
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_secretstore:secret_add",
                title="Add Secret",
                icon_class="mdi mdi-plus-thick",
                color="green",
            ),
            PluginMenuButton(
                link="plugins:netbox_secretstore:secret_import",
                title="Import Secret",
                icon_class="mdi mdi-upload",
                color="teal",
            ),
        ),
    ),
)
