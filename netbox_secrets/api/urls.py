from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

# Key management endpoints
router.register('user-keys', views.UserKeyViewSet)
router.register('session-key', views.SessionKeyViewSet)

# Secret management endpoints
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

# Utility endpoints
router.register('generate-rsa-key-pair', views.GenerateRSAKeyPairView, basename='generate-rsa-key-pair')

urlpatterns = router.urls
