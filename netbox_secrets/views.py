import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views.generic.base import View
from extras.signals import clear_webhooks
from netbox.views import generic
from utilities.exceptions import AbortRequest, PermissionsViolation
from utilities.forms import ConfirmationForm, restrict_form_fields
from utilities.utils import count_related, prepare_cloned_fields
from utilities.views import GetReturnURLMixin, ViewTab, register_model_view

from . import exceptions, filtersets, forms, models, tables, utils

#
# Mixins
#


class ObjectChildrenViewMixin(generic.ObjectChildrenView):
    def get_extra_context(self, request, instance):
        return {
            'table_config': f'{self.table.__name__}_config',
        }


#
# Secret roles
#


class SecretRoleListView(generic.ObjectListView):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    table = tables.SecretRoleTable
    filterset = filtersets.SecretRoleFilterSet
    filterset_form = forms.SecretRoleFilterForm


@register_model_view(models.SecretRole)
class SecretRoleView(generic.ObjectView):
    queryset = models.SecretRole.objects.prefetch_related('tags')


@register_model_view(models.SecretRole, 'secret')
class SecretRoleSecretView(ObjectChildrenViewMixin):
    queryset = models.SecretRole.objects.all()
    child_model = models.Secret
    table = tables.SecretTable
    filterset = filtersets.SecretFilterSet
    template_name = 'netbox_secrets/inc/view_tab.html'
    tab = ViewTab(
        label=_('Secrets'),
        badge=lambda obj: models.Secret.objects.filter(role=obj).count(),
        weight=500,
        hide_if_empty=True,
    )

    def get_children(self, request, parent):
        return models.Secret.objects.filter(role=parent)


@register_model_view(models.SecretRole, 'edit')
class SecretRoleEditView(generic.ObjectEditView):
    queryset = models.SecretRole.objects.prefetch_related('tags')
    form = forms.SecretRoleForm


@register_model_view(models.SecretRole, 'delete')
class SecretRoleDeleteView(generic.ObjectDeleteView):
    queryset = models.SecretRole.objects.prefetch_related('tags')


class SecretRoleBulkImportView(generic.BulkImportView):
    queryset = models.SecretRole.objects.prefetch_related('tags')
    model_form = forms.SecretRoleImportForm
    table = tables.SecretRoleTable


class SecretRoleBulkEditView(generic.BulkEditView):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    filterset = filtersets.SecretRoleFilterSet
    table = tables.SecretRoleTable
    form = forms.SecretRoleBulkEditForm


class SecretRoleBulkDeleteView(generic.BulkDeleteView):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    table = tables.SecretRoleTable


#
# Secrets
#


class SecretListView(generic.ObjectListView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    filterset = filtersets.SecretFilterSet
    filterset_form = forms.SecretFilterForm
    table = tables.SecretTable
    actions = ('bulk_delete', 'bulk_edit')


@register_model_view(models.Secret)
class SecretView(generic.ObjectView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')


@register_model_view(models.Secret, 'edit')
class SecretEditView(generic.ObjectEditView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    form = forms.SecretForm
    template_name = 'netbox_secrets/secret_edit.html'

    def alter_object(self, instance, request, url_args, url_kwargs):
        if not instance.pk:
            # Assign the assigned_object based on the URL parameters
            content_type = get_object_or_404(ContentType, pk=request.GET.get('assigned_object_type'))
            instance.assigned_object = get_object_or_404(
                content_type.model_class(),
                pk=request.GET.get('assigned_object_id'),
            )

        return instance

    def get_extra_addanother_params(self, request):
        return {
            'assigned_object_type': request.GET.get('assigned_object_type'),
            'assigned_object_id': request.GET.get('assigned_object_id'),
        }

    def dispatch(self, request, *args, **kwargs):

        # Check that the user has a valid UserKey
        try:
            uk = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            messages.warning(request, "This operation requires an active user key, but you don't have one.")
            return redirect('plugins:netbox_secrets:userkey')
        if not uk.is_active():
            messages.warning(request, "This operation is not available. Your user key has not been activated.")
            return redirect('plugins:netbox_secrets:userkey')

        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logger = logging.getLogger('netbox.views.ObjectEditView')
        obj = self.get_object(**kwargs)
        session_key = utils.get_session_key(request)

        # Take a snapshot for change logging (if editing an existing object)
        if obj.pk and hasattr(obj, 'snapshot'):
            obj.snapshot()

        obj = self.alter_object(obj, request, args, kwargs)

        form = self.form(data=request.POST, instance=obj)
        restrict_form_fields(form, request.user)

        if form.is_valid():
            logger.debug("Form validation was successful")
            try:
                with transaction.atomic():
                    object_created = form.instance.pk is None
                    obj = form.save(commit=False)

                    # We must have a session key in order to set the plaintext of a Secret
                    if form.cleaned_data['plaintext'] and session_key is None:
                        logger.debug("Unable to proceed: No session key was provided with the request")
                        form.add_error(
                            None,
                            "No session key was provided with the request. Unable to encrypt secret data.",
                        )

                    elif form.cleaned_data['plaintext']:
                        master_key = None
                        try:
                            sk = models.SessionKey.objects.get(userkey__user=request.user)
                            master_key = sk.get_master_key(session_key)
                        except models.SessionKey.DoesNotExist:
                            logger.debug("Unable to proceed: User has no session key assigned")
                            form.add_error(None, "No session key found for this user.")
                        except exceptions.InvalidKey:
                            logger.debug("Unable to proceed: Session key is invalid")
                            form.add_error(None, "Invalid session key provided.")

                        if master_key is not None:
                            logger.debug("Successfully resolved master key for encryption")
                            obj.plaintext = str(form.cleaned_data['plaintext'])
                            obj.encrypt(master_key)

                    if form.errors:
                        logger.debug("Form validation failed")
                        return render(
                            request,
                            self.template_name,
                            {
                                'object': obj,
                                'form': form,
                                'return_url': self.get_return_url(request, obj),
                                **self.get_extra_context(request, obj),
                            },
                        )

                    obj.save()
                    form.save_m2m()

                    msg = '{} {}'.format(
                        'Created' if object_created else 'Modified',
                        self.queryset.model._meta.verbose_name,
                    )
                    logger.info(f"{msg} {obj} (PK: {obj.pk})")
                    if hasattr(obj, 'get_absolute_url'):
                        msg = mark_safe(f'{msg} <a href="{obj.get_absolute_url()}">{escape(obj)}</a>')
                    else:
                        msg = f'{msg} {obj}'
                    messages.success(request, msg)

                    if '_addanother' in request.POST:
                        redirect_url = request.path

                        # If cloning is supported, pre-populate a new instance of the form
                        params = prepare_cloned_fields(obj)
                        params.update(self.get_extra_addanother_params(request))
                        if params:
                            if 'return_url' in request.GET:
                                params['return_url'] = request.GET.get('return_url')
                            redirect_url += f"?{params.urlencode()}"

                        return redirect(redirect_url)

                    return_url = self.get_return_url(request, obj)

                    return redirect(return_url)
            except (AbortRequest, PermissionsViolation) as e:
                logger.debug(e.message)
                form.add_error(None, e.message)
                clear_webhooks.send(sender=self)

        else:
            logger.debug("Form validation failed")

        return render(
            request,
            self.template_name,
            {
                'object': obj,
                'form': form,
                'return_url': self.get_return_url(request, obj),
                **self.get_extra_context(request, obj),
            },
        )


@register_model_view(models.Secret, 'delete')
class SecretDeleteView(generic.ObjectDeleteView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')


class SecretBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    filterset = filtersets.SecretFilterSet
    table = tables.SecretTable


class UserKeyView(LoginRequiredMixin, View):
    template_name = 'netbox_secrets/userkey.html'

    def get(self, request):
        try:
            userkey = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            userkey = None

        return render(
            request,
            self.template_name,
            {
                'object': userkey,
            },
        )


class UserKeyEditView(LoginRequiredMixin, GetReturnURLMixin, View):
    queryset = models.SessionKey.objects.all()
    template_name = 'netbox_secrets/userkey_edit.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            self.userkey = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            self.userkey = models.UserKey(user=request.user)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = forms.UserKeyForm(instance=self.userkey)
        return render(
            request,
            self.template_name,
            {
                'object': self.userkey,
                'form': form,
                'return_url': self.get_return_url(request, self.userkey),
            },
        )

    def post(self, request):
        logger = logging.getLogger('netbox.views.ObjectEditView')
        form = forms.UserKeyForm(data=request.POST, instance=self.userkey)
        if form.is_valid():
            uk = form.save(commit=False)
            uk.user = request.user
            uk.save()
            messages.success(request, "Your user key has been saved.")
            return redirect('plugins:netbox_secrets:userkey')
        else:
            logger.debug("Form validation failed")
            messages.error(request, "Unable to save your user key.")

        return render(
            request,
            self.template_name,
            {
                'userkey': self.userkey,
                'form': form,
            },
        )


@register_model_view(models.SessionKey, 'delete')
class SessionKeyDeleteView(generic.ObjectDeleteView):
    queryset = models.SessionKey.objects.all()

    def get_queryset(self, request):
        return super().get_queryset(request).filter(userkey__user=request.user)
