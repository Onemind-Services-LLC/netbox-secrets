from django.urls import include, path

from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

# Core model endpoints (CRUD operations)
router.register('user-keys', views.UserKeyViewSet)
router.register('session-keys', views.SessionKeyViewSet)
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

urlpatterns = [
    # Utility endpoints (non-CRUD operations)
    path('generate-rsa-key-pair/', views.GenerateRSAKeyPairView.as_view(), name='generate-rsa-key-pair'),
    path('user-keys/activate/', views.ActivateUserKeyView.as_view(), name='userkey-activate'),

    # Router URLs for CRUD endpoints
    path('', include(router.urls)),
]