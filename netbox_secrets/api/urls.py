from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

router.register('user-keys', views.UserKeyViewSet)
router.register('session-keys', views.SessionKeyViewSet)
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

# Miscellaneous
router.register('generate-rsa-key-pair', views.GenerateRSAKeyPairViewSet, basename='generate-rsa-key-pair')

urlpatterns = router.urls
