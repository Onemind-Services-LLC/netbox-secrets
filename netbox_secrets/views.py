import base64
import logging

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views.generic.base import View

from netbox.views import generic
from netbox_secrets.forms import SecretRoleFilterForm
from utilities.forms import ConfirmationForm
from utilities.utils import count_related
from utilities.views import ViewTab, register_model_view
from .filtersets import *
from .forms import *
from .models import SessionKey, UserKey
from .tables import *


def get_session_key(request):
    """
    Extract and decode the session key sent with a request. Returns None if no session key was provided.
    """
    session_key = request.COOKIES.get('session_key', None)
    if session_key is not None:
        return base64.b64decode(session_key)
    return session_key


#
# Secret roles
#

class SecretRoleListView(generic.ObjectListView):
    queryset = SecretRole.objects.annotate(
        secret_count=count_related(Secret, 'role')
    )
    table = SecretRoleTable
    filterset = SecretRoleFilterSet
    filterset_form = SecretRoleFilterForm


@register_model_view(SecretRole)
class SecretRoleView(generic.ObjectView):
    queryset = SecretRole.objects.all()


@register_model_view(SecretRole, 'secret')
class SecretRoleSecretView(generic.ObjectChildrenView):
    queryset = SecretRole.objects.all()
    child_model = Secret
    table = SecretTable
    filterset = SecretFilterSet
    template_name = 'netbox_secrets/inc/view_tab.html'
    tab = ViewTab(
        label=_('Secrets'),
        badge=lambda obj: Secret.objects.filter(role=obj).count(),
        weight=500,
        hide_if_empty=True
    )

    def get_children(self, request, parent):
        return Secret.objects.filter(role=parent)

    def get_extra_context(self, request, instance):
        return {
            'table_config': 'SecretTable_config',
        }


@register_model_view(SecretRole, 'edit')
class SecretRoleEditView(generic.ObjectEditView):
    queryset = SecretRole.objects.all()
    form = SecretRoleForm


@register_model_view(SecretRole, 'delete')
class SecretRoleDeleteView(generic.ObjectDeleteView):
    queryset = SecretRole.objects.all()


class SecretRoleBulkImportView(generic.BulkImportView):
    queryset = SecretRole.objects.all()
    model_form = SecretRoleImportForm
    table = SecretRoleTable


class SecretRoleBulkEditView(generic.BulkEditView):
    queryset = SecretRole.objects.annotate(
        secret_count=count_related(Secret, 'role')
    )
    filterset = SecretRoleFilterSet
    table = SecretRoleTable
    form = SecretRoleBulkEditForm


class SecretRoleBulkDeleteView(generic.BulkDeleteView):
    queryset = SecretRole.objects.annotate(
        secret_count=count_related(Secret, 'role')
    )
    table = SecretRoleTable


#
# Secrets
#

class SecretListView(generic.ObjectListView):
    queryset = Secret.objects.all()
    filterset = SecretFilterSet
    filterset_form = SecretFilterForm
    table = SecretTable
    action_buttons = ('add', 'import', 'export')


@register_model_view(Secret)
class SecretView(generic.ObjectView):
    queryset = Secret.objects.all()


@register_model_view(Secret, 'edit')
class SecretEditView(generic.ObjectEditView):
    queryset = Secret.objects.all()
    form = SecretForm
    template_name = 'netbox_secrets/secret_edit.html'

    def dispatch(self, request, *args, **kwargs):

        # Check that the user has a valid UserKey
        try:
            uk = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
            messages.warning(request, "This operation requires an active user key, but you don't have one.")
            return redirect('plugins:netbox_secrets:userkey')
        if not uk.is_active():
            messages.warning(request, "This operation is not available. Your user key has not been activated.")
            return redirect('plugins:netbox_secrets:userkey')

        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        logger = logging.getLogger('netbox.views.ObjectEditView')
        session_key = get_session_key(request)
        secret = self.get_object(**kwargs)
        form = self.form(request.POST, instance=secret)

        if form.is_valid():
            logger.debug("Form validation was successful")
            secret = form.save(commit=False)

            # We must have a session key in order to set the plaintext of a Secret
            if form.cleaned_data['plaintext'] and session_key is None:
                logger.debug("Unable to proceed: No session key was provided with the request")
                form.add_error(None, "No session key was provided with the request. Unable to encrypt secret data.")

            elif form.cleaned_data['plaintext']:
                master_key = None
                try:
                    sk = SessionKey.objects.get(userkey__user=request.user)
                    master_key = sk.get_master_key(session_key)
                except SessionKey.DoesNotExist:
                    logger.debug("Unable to proceed: User has no session key assigned")
                    form.add_error(None, "No session key found for this user.")

                if master_key is not None:
                    logger.debug("Successfully resolved master key for encryption")
                    secret.plaintext = str(form.cleaned_data['plaintext'])
                    secret.encrypt(master_key)

            secret.save()
            form.save_m2m()

            msg = '{} secret'.format('Created' if not form.instance.pk else 'Modified')
            logger.info(f"{msg} {secret} (PK: {secret.pk})")
            msg = f'{msg} <a href="{secret.get_absolute_url()}">{escape(secret)}</a>'
            messages.success(request, mark_safe(msg))

            return redirect(self.get_return_url(request, secret))

        else:
            logger.debug("Form validation failed")

        return render(request, self.template_name, {
            'obj': secret,
            'obj_type': self.queryset.model._meta.verbose_name,
            'form': form,
            'return_url': self.get_return_url(request, secret),
        })


@register_model_view(Secret, 'delete')
class SecretDeleteView(generic.ObjectDeleteView):
    queryset = Secret.objects.all()


class SecretBulkImportView(generic.BulkImportView):
    queryset = Secret.objects.all()
    model_form = SecretImportForm
    table = SecretTable
    template_name = 'netbox_secrets/secret_bulk_import.html'
    widget_attrs = {'class': 'requires-session-key'}

    master_key = None

    def _save_obj(self, obj_form, request):
        """
        Encrypt each object before saving it to the database.
        """
        obj = obj_form.save(commit=False)
        obj.encrypt(self.master_key)
        obj.save()
        return obj

    def post(self, request):

        # Grab the session key from cookies.
        session_key = request.COOKIES.get('session_key')
        if session_key:

            # Attempt to derive the master key using the provided session key.
            try:
                sk = SessionKey.objects.get(userkey__user=request.user)
                self.master_key = sk.get_master_key(base64.b64decode(session_key))
            except SessionKey.DoesNotExist:
                messages.error(request, "No session key found for this user.")

            if self.master_key is not None:
                return super().post(request)
            else:
                messages.error(request, "Invalid private key! Unable to encrypt secret data.")

        else:
            messages.error(request, "No session key was provided with the request. Unable to encrypt secret data.")

        return render(request, self.template_name, {
            'form': self._import_form(request.POST),
            'fields': self.model_form().fields,
            'obj_type': self.model_form._meta.model._meta.verbose_name,
            'return_url': self.get_return_url(request),
        })


class SecretBulkEditView(generic.BulkEditView):
    queryset = Secret.objects.prefetch_related('role')
    filterset = SecretFilterSet
    table = SecretTable
    form = SecretBulkEditForm


class SecretBulkDeleteView(generic.BulkDeleteView):
    queryset = Secret.objects.prefetch_related('role')
    filterset = SecretFilterSet
    table = SecretTable


# @register_model_view(UserKey)
class UserKeyView(LoginRequiredMixin, View):
    template_name = 'netbox_secrets/userkey.html'

    def get(self, request):
        try:
            userkey = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
            userkey = None

        return render(request, self.template_name, {
            'object': userkey,
            'active_tab': 'userkey',
        })


# @register_model_view(UserKey, 'edit')
class UserKeyEditView(LoginRequiredMixin, View):
    queryset = SessionKey.objects.all()
    template_name = 'netbox_secrets/userkey_edit.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            self.userkey = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
            self.userkey = UserKey(user=request.user)

        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        form = UserKeyForm(instance=self.userkey)
        print(self.template_name)
        return render(request, self.template_name, {
            'object': self.userkey,
            'form': form,
            'active_tab': 'userkey',
        })

    def post(self, request):
        form = UserKeyForm(data=request.POST, instance=self.userkey)
        if form.is_valid():
            uk = form.save(commit=False)
            uk.user = request.user
            uk.save()
            messages.success(request, "Your user key has been saved.")
            return redirect('plugins:netbox_secrets:userkey')

        return render(request, self.template_name, {
            'userkey': self.userkey,
            'form': form,
            'active_tab': 'userkey',
        })


# @register_model_view(SessionKey, 'delete')
class SessionKeyDeleteView(generic.ObjectDeleteView):
    queryset = SessionKey.objects.all()

    def get(self, request):
        sessionkey = get_object_or_404(SessionKey, userkey__user=request.user)
        form = ConfirmationForm()

        return render(request, 'netbox_secrets/sessionkey_delete.html', {
            'object': sessionkey,
            'obj_type': sessionkey._meta.verbose_name,
            'form': form,
            'return_url': reverse('plugins:netbox_secrets:userkey'),
        })

    def post(self, request):
        sessionkey = get_object_or_404(SessionKey, userkey__user=request.user)
        form = ConfirmationForm(request.POST)
        if form.is_valid():
            # Delete session key
            sessionkey.delete()
            messages.success(request, "Session key deleted")

            # Delete cookie
            response = redirect('plugins:netbox_secrets:userkey')
            response.delete_cookie('session_key')

            return response

        return render(request, 'netbox_secrets/sessionkey_delete.html', {
            'obj_type': sessionkey._meta.verbose_name,
            'form': form,
            'return_url': reverse('plugins:netbox_secrets:userkey'),
        })
