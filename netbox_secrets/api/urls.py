from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

router.register('user-keys', views.UserKeyViewSet)
router.register('session-keys', views.SessionKeyViewSet)
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

# Miscellaneous
router.register('get-session-key', views.GetSessionKeyViewSet, basename='get-session-key')
router.register('generate-rsa-key-pair', views.GenerateRSAKeyPairViewSet, basename='generate-rsa-key-pair')
router.register('activate-user-key', views.ActivateUserKeyViewSet, basename='activate-user-keys')

# Zero-knowledge tenant crypto
router.register('tenant-memberships', views.TenantMembershipViewSet)
router.register('tenant-service-accounts', views.TenantServiceAccountViewSet)
router.register('service-account-activation', views.ServiceAccountActivationViewSet, basename='service-account-activation')
router.register('tenant-secrets', views.TenantSecretViewSet)
router.register('svc/secrets', views.ServiceAccountSecretViewSet, basename='service-account-secrets')

urlpatterns = router.urls
