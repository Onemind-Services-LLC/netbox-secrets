from django.urls import include, path
from utilities.urls import get_model_urls

from .views import *

app_name = 'netbox_secrets'

urlpatterns = [

    # Secret roles
    path('secret-roles/', SecretRoleListView.as_view(), name='secretrole_list'),
    path('secret-roles/add/', SecretRoleEditView.as_view(), name='secretrole_add'),
    path('secret-roles/import/', SecretRoleBulkImportView.as_view(), name='secretrole_import'),
    path('secret-roles/edit/', SecretRoleBulkEditView.as_view(), name='secretrole_bulk_edit'),
    path('secret-roles/delete/', SecretRoleBulkDeleteView.as_view(), name='secretrole_bulk_delete'),
    path('secret-roles/<int:pk>/', include(get_model_urls('netbox_secrets', 'secretrole'))),

    # Secrets
    path('secrets/', SecretListView.as_view(), name='secret_list'),
    path('secrets/add/', SecretEditView.as_view(), name='secret_add'),
    path('secrets/import/', SecretBulkImportView.as_view(), name='secret_import'),
    path('secrets/edit/', SecretBulkEditView.as_view(), name='secret_bulk_edit'),
    path('secrets/delete/', SecretBulkDeleteView.as_view(), name='secret_bulk_delete'),
    path('secrets/<int:pk>/', include(get_model_urls('netbox_secrets', 'secret'))),

    # User
    path('user-key/', UserKeyView.as_view(), name='userkey'),
    path('user-key/edit/', UserKeyEditView.as_view(), name='userkey_edit'),
    path('session-key/delete/', SessionKeyDeleteView.as_view(), name='sessionkey_delete'),
]
