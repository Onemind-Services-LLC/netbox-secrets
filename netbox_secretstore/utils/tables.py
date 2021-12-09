from utilities.tables import ButtonsColumn


class PluginButtonsColumn(ButtonsColumn):
    """
    Render edit, delete, and changelog buttons for an object.

    :param model: Model class to use for calculating URL view names
    :param prepend_content: Additional template content to render in the column (optional)
    :param return_url_extra: String to append to the return URL (e.g. for specifying a tab) (optional)
    """

    template_code = """
    {{% load plugin_buttons %}}
    {{% if "changelog" in buttons %}}
        {{% plugin_tr_changelog_button record %}}
    {{% endif %}}
    {{% if "edit" in buttons and perms.{app_label}.change_{model_name} %}}
        {{% plugin_tr_edit_button record return_url_extra %}}
    {{% endif %}}
    {{% if "delete" in buttons and perms.{app_label}.delete_{model_name} %}}
        {{% plugin_tr_delete_button record return_url_extra %}}
    {{% endif %}}
    """
