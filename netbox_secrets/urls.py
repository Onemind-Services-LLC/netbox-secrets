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

    # Tenant Crypto - Zero-knowledge secret sharing
    path('tenant-memberships/', include(get_model_urls('netbox_secrets', 'tenantmembership', detail=False))),
    path('tenant-memberships/<int:pk>/', include(get_model_urls('netbox_secrets', 'tenantmembership'))),
    path('tenant-service-accounts/', include(get_model_urls('netbox_secrets', 'tenantserviceaccount', detail=False))),
    path('tenant-service-accounts/<int:pk>/', include(get_model_urls('netbox_secrets', 'tenantserviceaccount'))),
    path('tenant-secrets/', include(get_model_urls('netbox_secrets', 'tenantsecret', detail=False))),
    path('tenant-secrets/<int:pk>/', include(get_model_urls('netbox_secrets', 'tenantsecret'))),

    # Tenant Crypto Setup (Passkey enrollment)
    path('tenant-crypto/setup/', views.TenantCryptoSetupView.as_view(), name='tenant_crypto_setup'),
    path('tenant-crypto/setup/<int:tenant_id>/', views.TenantCryptoSetupView.as_view(), name='tenant_crypto_setup_tenant'),

    # Service Account Activation
    path('tenant-service-accounts/<int:pk>/activate/', views.ServiceAccountActivateView.as_view(), name='tenantserviceaccount_activate'),
]
