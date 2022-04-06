from django.urls import path

from netbox.views.generic import ObjectChangeLogView, ObjectJournalView
from .views import *
from .models import Secret, SecretRole

urlpatterns = [

    # Secret roles
    path('secret-roles/', SecretRoleListView.as_view(), name='secretrole_list'),
    path('secret-roles/add/', SecretRoleEditView.as_view(), name='secretrole_add'),
    path('secret-roles/import/', SecretRoleBulkImportView.as_view(), name='secretrole_import'),
    path('secret-roles/edit/', SecretRoleBulkEditView.as_view(), name='secretrole_bulk_edit'),
    path('secret-roles/delete/', SecretRoleBulkDeleteView.as_view(), name='secretrole_bulk_delete'),
    path('secret-roles/<int:pk>/', SecretRoleView.as_view(), name='secretrole'),
    path('secret-roles/<int:pk>/edit/', SecretRoleEditView.as_view(), name='secretrole_edit'),
    path('secret-roles/<int:pk>/delete/', SecretRoleDeleteView.as_view(), name='secretrole_delete'),
    path('secret-roles/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='secretrole_changelog', kwargs={'model': SecretRole}),

    # Secrets
    path('secrets/', SecretListView.as_view(), name='secret_list'),
    path('secrets/add/', SecretEditView.as_view(), name='secret_add'),
    path('secrets/import/', SecretBulkImportView.as_view(), name='secret_import'),
    path('secrets/edit/', SecretBulkEditView.as_view(), name='secret_bulk_edit'),
    path('secrets/delete/', SecretBulkDeleteView.as_view(), name='secret_bulk_delete'),
    path('secrets/<int:pk>/', SecretView.as_view(), name='secret'),
    path('secrets/<int:pk>/edit/', SecretEditView.as_view(), name='secret_edit'),
    path('secrets/<int:pk>/delete/', SecretDeleteView.as_view(), name='secret_delete'),
    path('secrets/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='secret_changelog', kwargs={'model': Secret}),
    path('secrets/<int:pk>/journal/', ObjectJournalView.as_view(), name='secret_journal', kwargs={'model': Secret}),

    # User
    path('user-key/', UserKeyView.as_view(), name='userkey'),
    path('user-key/edit/', UserKeyEditView.as_view(), name='userkey_edit'),
    path('session-key/delete/', SessionKeyDeleteView.as_view(), name='sessionkey_delete'),
]
