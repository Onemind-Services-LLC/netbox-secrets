"""
Remove everything the NetBox Secrets plugin has put into the NetBox database.

This command must be run *before* the plugin is removed from ``PLUGINS`` and uninstalled with pip, because it
needs the plugin's models and migrations. See docs/installation.md for the full procedure.
"""

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.models import Count, F, ProtectedError, Q

APP_LABEL = 'netbox_secrets'
CONFIRMATION_WORD = 'uninstall'


def get_content_types():
    return ContentType.objects.filter(app_label=APP_LABEL)


def get_plugin_tables():
    """Names of the database tables that currently exist for the plugin."""
    with connection.cursor() as cursor:
        tables = connection.introspection.table_names(cursor)
    return sorted(t for t in tables if t.startswith(f'{APP_LABEL}_'))


def get_shared_models():
    """
    Models from NetBox core that can be scoped to object types (and therefore to the plugin's models). Each
    entry is a model class whose ``object_types`` relation points at ContentType/ObjectType.
    """
    from extras.models import (
        CustomField,
        CustomLink,
        EventRule,
        ExportTemplate,
        SavedFilter,
        Tag,
    )
    from users.models import ObjectPermission

    return [CustomField, CustomLink, EventRule, ExportTemplate, SavedFilter, Tag, ObjectPermission]


def get_scoped_only_to_plugin(model, content_types):
    """
    Instances of ``model`` whose object types consist exclusively of the plugin's types. Once the plugin is gone
    these are meaningless: they apply to nothing.
    """
    ids = list(content_types.values_list('pk', flat=True))
    pks = (
        model.objects.annotate(
            total_types=Count('object_types', distinct=True),
            plugin_types=Count('object_types', filter=Q(object_types__in=ids), distinct=True),
        )
        .filter(plugin_types__gt=0, total_types=F('plugin_types'))
        .values_list('pk', flat=True)
    )
    return model.objects.filter(pk__in=list(pks))


class Command(BaseCommand):
    help = (
        'Delete all data, database tables, migration records, permissions and content types created by the '
        'NetBox Secrets plugin. Run this BEFORE removing the plugin from PLUGINS and uninstalling it. '
        'Encrypted secrets and user keys are destroyed and cannot be recovered.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Only report what would be removed.',
        )
        parser.add_argument(
            '--no-input',
            '--noinput',
            action='store_false',
            dest='interactive',
            help='Do not ask for confirmation.',
        )
        parser.add_argument(
            '--delete-orphans',
            action='store_true',
            help=(
                'Also delete custom fields, custom links, event rules, export templates, saved filters, tags and '
                'object permissions that only applied to the plugin\'s models. Without this flag they are kept '
                '(unlinked from the plugin) and listed in the output.'
            ),
        )

    def handle(self, *args, **options):
        content_types = get_content_types()
        tables = get_plugin_tables()
        if not content_types.exists() and not tables:
            self.stdout.write('Nothing to do: the NetBox Secrets plugin has no content types or tables.')
            return

        report = self.build_report(content_types, tables)
        self.print_report(report)

        if options['dry_run']:
            self.stdout.write(self.style.WARNING('Dry run: nothing was changed.'))
            return

        if options['interactive']:
            self.stdout.write('')
            self.stdout.write(
                self.style.WARNING(
                    'This permanently destroys all secrets, roles and user keys. Make a database backup first.'
                )
            )
            answer = input(f'Type "{CONFIRMATION_WORD}" to continue: ')
            if answer.strip().lower() != CONFIRMATION_WORD:
                raise CommandError('Aborted.')

        with transaction.atomic():
            self.uninstall(options['delete_orphans'])

        self.stdout.write(self.style.SUCCESS('NetBox Secrets data has been removed.'))
        self.stdout.write(
            'Next: remove "netbox_secrets" from PLUGINS and PLUGINS_CONFIG, run "pip uninstall netbox-secrets", '
            'then restart NetBox.'
        )

    def build_report(self, content_types, tables):
        from core.models import ObjectChange

        report = {'tables': tables}
        counts = {}
        for model in self.get_plugin_models():
            if model._meta.db_table in tables:
                counts[model._meta.verbose_name_plural] = model.objects.count()
        report['rows'] = counts
        report['object_changes'] = ObjectChange.objects.filter(
            Q(changed_object_type__in=content_types) | Q(related_object_type__in=content_types)
        ).count()
        report['content_types'] = content_types.count()
        report['permissions'] = Permission.objects.filter(content_type__in=content_types).count()
        report['orphans'] = {
            model._meta.verbose_name_plural: list(
                get_scoped_only_to_plugin(model, content_types).values_list('name', flat=True)
            )
            for model in get_shared_models()
        }
        report['linked'] = {
            model._meta.verbose_name_plural: model.objects.filter(object_types__in=content_types).distinct().count()
            for model in get_shared_models()
        }
        return report

    def print_report(self, report):
        self.stdout.write(self.style.MIGRATE_HEADING('NetBox Secrets uninstall'))
        self.stdout.write(f'Database tables to drop: {", ".join(report["tables"]) or "none"}')
        for name, count in report['rows'].items():
            self.stdout.write(f'  {name}: {count} row(s)')
        self.stdout.write(f'Changelog entries to delete: {report["object_changes"]}')
        self.stdout.write(f'Content types to delete: {report["content_types"]}')
        self.stdout.write(f'Permissions to delete: {report["permissions"]}')
        for name, count in report['linked'].items():
            if count:
                self.stdout.write(f'  {name} linked to plugin models (links will be removed): {count}')
        for name, names in report['orphans'].items():
            if names:
                self.stdout.write(f'  {name} that only applied to plugin models: {", ".join(sorted(names))}')

    @staticmethod
    def get_plugin_models():
        from django.apps import apps

        return list(apps.get_app_config(APP_LABEL).get_models())

    def uninstall(self, delete_orphans):
        from core.models import ObjectChange

        content_types = get_content_types()

        # Change log entries reference content types through PROTECT foreign keys, so they must go first.
        ObjectChange.objects.filter(
            Q(changed_object_type__in=content_types) | Q(related_object_type__in=content_types)
        ).delete()

        if delete_orphans:
            for model in get_shared_models():
                get_scoped_only_to_plugin(model, content_types).delete()

        # Deleting the content types cascades to permissions, journal entries, search cache entries and the
        # object type links of custom fields, tags, export templates, saved filters and object permissions. It
        # must happen while the plugin's tables still exist, because Django also walks the plugin's own models.
        try:
            content_types.delete()
        except ProtectedError as exc:
            raise CommandError(f'Cannot delete the plugin content types: {exc}') from exc

        # PostgreSQL refuses to alter a table while deferred constraint checks from the deletes above are still
        # pending, so run them now.
        with connection.cursor() as cursor:
            cursor.execute('SET CONSTRAINTS ALL IMMEDIATE')

        self.unapply_migrations()

    def unapply_migrations(self):
        """
        Reverse every migration of the plugin, which drops its tables, triggers and functions and removes its rows
        from django_migrations. The migration executor is used directly because the migrate command would
        recreate the content types in its post_migrate step.
        """
        executor = MigrationExecutor(connection)
        targets = [(APP_LABEL, None)]
        plan = executor.migration_plan(targets)
        executor.migrate(targets, plan=plan)
