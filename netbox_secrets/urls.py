from django.urls import include, path

from utilities.urls import get_model_urls
from . import views

app_name = 'netbox_secrets'

urlpatterns = [
    path('secret-roles/', include(get_model_urls('netbox_secrets', 'secretrole', detail=False))),
    path('secret-roles/<int:pk>/', include(get_model_urls('netbox_secrets', 'secretrole'))),
    path('secrets/', include(get_model_urls('netbox_secrets', 'secret', detail=False))),
    path('secrets/<int:pk>/', include(get_model_urls('netbox_secrets', 'secret'))),
    path('user-keys/', include(get_model_urls('netbox_secrets', 'userkey', detail=False))),
    path('user-keys/<int:pk>/', include(get_model_urls('netbox_secrets', 'userkey'))),
]
