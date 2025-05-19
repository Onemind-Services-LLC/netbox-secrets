import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views.generic.base import View

from core.signals import clear_events
from netbox.views import generic
from netbox_secrets.models import UserKey
from utilities.exceptions import AbortRequest, PermissionsViolation
from utilities.forms import restrict_form_fields
from utilities.query import count_related
from utilities.querydict import prepare_cloned_fields
from utilities.views import GetRelatedModelsMixin, GetReturnURLMixin, ViewTab, register_model_view
from . import constants, exceptions, filtersets, forms, models, tables, utils


#
# Secret roles
#


@register_model_view(models.SecretRole, 'list', path='', detail=False)
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
class SecretRoleSecretView(generic.ObjectChildrenView):
    queryset = models.SecretRole.objects.all()
    child_model = models.Secret
    table = tables.SecretTable
    filterset = filtersets.SecretFilterSet
    tab = ViewTab(
        label=_('Secrets'),
        badge=lambda obj: models.Secret.objects.filter(role=obj).count(),
        weight=500,
        hide_if_empty=True,
    )

    def get_children(self, request, parent):
        return models.Secret.objects.filter(role=parent)


@register_model_view(models.SecretRole, 'add', detail=False)
@register_model_view(models.SecretRole, 'edit')
class SecretRoleEditView(generic.ObjectEditView):
    queryset = models.SecretRole.objects.prefetch_related('tags')
    form = forms.SecretRoleForm


@register_model_view(models.SecretRole, 'delete')
class SecretRoleDeleteView(generic.ObjectDeleteView):
    queryset = models.SecretRole.objects.prefetch_related('tags')


@register_model_view(models.SecretRole, 'bulk_import', detail=False)
class SecretRoleBulkImportView(generic.BulkImportView):
    queryset = models.SecretRole.objects.prefetch_related('tags')
    model_form = forms.SecretRoleImportForm
    table = tables.SecretRoleTable


@register_model_view(models.SecretRole, 'bulk_edit', path='edit', detail=False)
class SecretRoleBulkEditView(generic.BulkEditView):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    filterset = filtersets.SecretRoleFilterSet
    table = tables.SecretRoleTable
    form = forms.SecretRoleBulkEditForm


@register_model_view(models.SecretRole, 'bulk_delete', path='delete', detail=False)
class SecretRoleBulkDeleteView(generic.BulkDeleteView):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    table = tables.SecretRoleTable


#
# Secrets
#


@register_model_view(models.Secret, 'list', path='', detail=False)
class SecretListView(generic.ObjectListView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    filterset = filtersets.SecretFilterSet
    filterset_form = forms.SecretFilterForm
    table = tables.SecretTable
    actions = {
        "export": {"view"},
        "bulk_edit": {"change"},
        "bulk_delete": {"delete"},
    }


@register_model_view(models.Secret)
class SecretView(GetRelatedModelsMixin, generic.ObjectView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')


@register_model_view(models.Secret, 'add', detail=False)
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
            return redirect('plugins:netbox_secrets:userkey_add')
        if not uk.is_active():
            messages.warning(request, "This operation is not available. Your user key has not been activated.")
            return redirect('plugins:netbox_secrets:userkey', pk=uk.pk)

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
                clear_events.send(sender=self)

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


@register_model_view(models.Secret, 'bulk_edit', path='edit', detail=False)
class SecretBulkEditView(generic.BulkEditView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    filterset = filtersets.SecretFilterSet
    table = tables.SecretTable
    form = forms.SecretBulkEditForm


@register_model_view(models.Secret, 'bulk_delete', path='delete', detail=False)
class SecretBulkDeleteView(generic.BulkDeleteView):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    filterset = filtersets.SecretFilterSet
    table = tables.SecretTable


#
# User Key
#


@register_model_view(models.UserKey, 'list', path='', detail=False)
class UserKeyListView(generic.ObjectListView):
    queryset = models.UserKey.objects.all()
    table = tables.UserKeyTable
    filterset = filtersets.UserKeyFilterSet
    template_name = 'netbox_secrets/userkey_list.html'

    def get_extra_context(self, request):
        user_key = UserKey.objects.filter(user=request.user).first()
        return {
            'user_key': user_key,
        }


@register_model_view(models.UserKey)
class UserKeyView(generic.ObjectView):
    queryset = models.UserKey.objects.all()
    template_name = 'netbox_secrets/userkey.html'


@register_model_view(models.UserKey, 'delete')
class UserKeyDeleteView(generic.ObjectDeleteView):
    queryset = UserKey.objects.all()


@register_model_view(models.UserKey, 'add', detail=False)
@register_model_view(models.UserKey, 'edit')
class UserKeyEditView(LoginRequiredMixin, GetReturnURLMixin, View):
    queryset = models.UserKey.objects.all()
    form = forms.UserKeyForm
    template_name = 'netbox_secrets/userkey_edit.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            self.userkey = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            self.userkey = models.UserKey(user=request.user)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(
            request,
            self.template_name,
            {
                'object': self.userkey,
                'form': self.form,
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
            return redirect('plugins:netbox_secrets:userkey', pk=uk.pk)
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


@register_model_view(models.UserKey, 'activate', path='userkey_activate', detail=False)
class ActivateUserkeyView(LoginRequiredMixin, GetReturnURLMixin, View):
    queryset = models.UserKey.objects.all()
    template_name = 'netbox_secrets/activate_keys.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            self.userkey = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            self.userkey = models.UserKey(user=request.user)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = forms.ActivateUserKeyForm()
        return render(
            request,
            self.template_name,
            {
                'form': form,
            },
        )

    def post(self, request):
        if not request.user.has_perm('netbox_secrets.change_userkey'):
            raise PermissionDenied("You do not have permission to activate User Keys.")

        if not self.userkey or not self.userkey.is_active():
            messages.error(request, "You do not have an active User Key.")
            return redirect('plugins:netbox_secrets:userkey_activate')

        form = forms.ActivateUserKeyForm(request.POST)
        if form.is_valid():
            master_key = self.userkey.get_master_key(form.cleaned_data['secret_key'])
            user_keys = form.cleaned_data['user_keys']
            if master_key:
                for user_key in user_keys:
                    user_key.activate(master_key)
                    messages.success(request, f"Successfully activated {len(user_keys)} user keys.")
                    return redirect("plugins:netbox_secrets:userkey_list")
            else:
                messages.error(request, "Invalid Private Key.")

        return render(request, self.template_name, {'form': form})


class SessionKeyDeleteView(generic.ObjectDeleteView):
    queryset = models.SessionKey.objects.all()

    def get_queryset(self, request):
        return super().get_queryset(request).filter(userkey__user=request.user)

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        # Delete the cookie
        response.delete_cookie(constants.SESSION_COOKIE_NAME)
        return response
