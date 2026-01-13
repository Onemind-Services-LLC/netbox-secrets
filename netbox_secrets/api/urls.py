from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

# Core model endpoints
router.register('user-keys', views.UserKeyViewSet)
router.register('session-keys', views.SessionKeyViewSet)
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

# Utility endpoints
router.register('generate-rsa-key-pair', views.GenerateRSAKeyPairViewSet, basename='generate-rsa-key-pair')
router.register('activate-user-key', views.ActivateUserKeyViewSet, basename='activate-user-keys')

urlpatterns = router.urls
