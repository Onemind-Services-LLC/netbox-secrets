from django.urls import include, path
from utilities.urls import get_model_urls

from . import views

urlpatterns = [
    # Secret roles
    path('secret-roles/', include(get_model_urls('netbox_secrets', 'secretrole', detail=False))),
    path('secret-roles/<int:pk>/', include(get_model_urls('netbox_secrets', 'secretrole'))),
    # Secrets
    path('secrets/', include(get_model_urls('netbox_secrets', 'secret', detail=False))),
    path('secrets/<int:pk>/', include(get_model_urls('netbox_secrets', 'secret'))),
    # User
    path('user-keys/', include(get_model_urls('netbox_secrets', 'userkey', detail=False))),
    path('user-keys/<int:pk>/', include(get_model_urls('netbox_secrets', 'userkey'))),
    # Session Key
    path('session-key/delete/', views.SessionKeyDeleteView.as_view(), name='sessionkey_delete'),
]
