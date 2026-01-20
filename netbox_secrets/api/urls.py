from django.urls import include, path

from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.APIRootView = views.SecretsRootView

# Core model endpoints (CRUD operations)
router.register('user-keys', views.UserKeyViewSet)
router.register('secret-roles', views.SecretRoleViewSet)
router.register('secrets', views.SecretViewSet)

urlpatterns = [
    path('session-key/', views.SessionKeyViewSet.as_view(), name='session-key'),
    path('generate-rsa-key-pair/', views.GenerateRSAKeyPairView.as_view(), name='generate-rsa-key-pair'),

    # Router URLs for CRUD endpoints
    path('', include(router.urls)),
]
