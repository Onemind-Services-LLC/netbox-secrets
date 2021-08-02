from netbox import navigation_menu

SECRETS_MENU = navigation_menu.Menu(
    label="Secrets",
    icon_class="mdi mdi-key",
    groups=(
        navigation_menu.MenuGroup(
            label="User",
            items=(
                navigation_menu.MenuItem(
                    link_text="User Key", link="plugins:netbox_secretstore:userkey"
                ),
            ),
        ),
        navigation_menu.MenuGroup(
            label="Secrets",
            items=(
                navigation_menu.MenuItem(
                    link_text="Secret Roles",
                    link="plugins:netbox_secretstore:secretrole_list",
                    buttons=(
                        navigation_menu.MenuItemButton(
                            link="plugins:netbox_secretstore:secretrole_add",
                            title="Add Secret Role",
                            icon_class="mdi mdi-plus-thick",
                            color="success",
                        ),
                        navigation_menu.MenuItemButton(
                            link="plugins:netbox_secretstore:secretrole_import",
                            title="Import Secret Role",
                            icon_class="mdi mdi-upload",
                            color="info",
                        ),
                    ),
                ),
                navigation_menu.MenuItem(
                    link_text="Secrets",
                    link="plugins:netbox_secretstore:secret_list",
                    buttons=(
                        navigation_menu.MenuItemButton(
                            link="plugins:netbox_secretstore:secret_add",
                            title="Add Secret",
                            icon_class="mdi mdi-plus-thick",
                            color="success",
                        ),
                        navigation_menu.MenuItemButton(
                            link="plugins:netbox_secretstore:secret_import",
                            title="Import Secret",
                            icon_class="mdi mdi-upload",
                            color="info",
                        ),
                    ),
                ),
            ),
        ),
    ),
)

navigation_menu.MENUS.append(SECRETS_MENU)
