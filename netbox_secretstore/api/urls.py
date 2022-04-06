from netbox.api import NetBoxRouter
from . import views


router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

# Secrets
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

# Miscellaneous
router.register('get-session-key', views.GetSessionKeyViewSet, basename='get-session-key')
router.register('generate-rsa-key-pair', views.GenerateRSAKeyPairViewSet, basename='generate-rsa-key-pair')

urlpatterns = router.urls
