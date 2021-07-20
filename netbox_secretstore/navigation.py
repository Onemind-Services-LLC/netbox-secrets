from netbox import navigation_menu

SECRETS_MENU = navigation_menu.Menu(
    label='Secrets',
    icon="domain",
    groups=(
        navigation_menu.MenuGroup(
            label="User",
            items=(
                navigation_menu.MenuItem(label="User Key", url='plugins:netbox_secretstore:userkey', add_url=None, import_url=None),
            )
        ),
        navigation_menu.MenuGroup(
            label="Secrets",
            items=(
                navigation_menu.MenuItem(label="Secret Roles", url='plugins:netbox_secretstore:secretrole_list', add_url='plugins:netbox_secretstore:secretrole_add', import_url='plugins:netbox_secretstore:secretrole_import'),
                navigation_menu.MenuItem(label="Secrets", url='plugins:netbox_secretstore:secret_list', add_url='plugins:netbox_secretstore:secret_add', import_url='plugins:netbox_secretstore:secret_import'),
            )
        )
    )
)

navigation_menu.MENUS = navigation_menu.MENUS + (SECRETS_MENU, )
