import base64

from Crypto.PublicKey import RSA
from django.conf import settings
from django.http import HttpResponseBadRequest
from drf_spectacular import utils as drf_utils
from netbox.api.viewsets import BaseViewSet, NetBoxModelViewSet, mixins
from rest_framework import mixins as drf_mixins, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.routers import APIRootView
from rest_framework.viewsets import ReadOnlyModelViewSet, ViewSet
from utilities.query import count_related

from . import serializers
from .. import constants, exceptions, filtersets, models
from ..models.groups import ServiceAccountActivation

plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets', {})
public_key_size = plugin_settings.get('public_key_size')

ERR_USERKEY_MISSING = "No UserKey found for the current user."
ERR_USERKEY_INACTIVE = "UserKey has not been activated for decryption."
ERR_PRIVKEY_MISSING = "Private key was not provided."
ERR_PRIVKEY_INVALID = "Invalid private key."


class SecretsRootView(APIRootView):
    """
    Secrets API root view
    """

    def get_view_name(self):
        return 'Secrets'


#
# User Key
#
class UserKeyViewSet(ReadOnlyModelViewSet):
    queryset = models.UserKey.objects.all()
    serializer_class = serializers.UserKeySerializer
    filterset_class = filtersets.UserKeyFilterSet


#
# Secret Roles
#


class SecretRoleViewSet(NetBoxModelViewSet):
    queryset = models.SecretRole.objects.annotate(secret_count=count_related(models.Secret, 'role')).prefetch_related(
        'tags',
    )
    serializer_class = serializers.SecretRoleSerializer
    filterset_class = filtersets.SecretRoleFilterSet


#
# Secrets
#


class SecretViewSet(NetBoxModelViewSet):
    queryset = models.Secret.objects.prefetch_related('role', 'tags')
    serializer_class = serializers.SecretSerializer
    filterset_class = filtersets.SecretFilterSet

    master_key = None

    def get_serializer_context(self):
        # Make the master key available to the serializer for encrypting plaintext values
        context = super().get_serializer_context()
        context['master_key'] = self.master_key

        return context

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        if request.user.is_authenticated:
            # Read session key from HTTP cookie or header if it has been provided. The session key must be provided in
            # order to encrypt/decrypt secrets.
            if constants.SESSION_COOKIE_NAME in request.COOKIES:
                session_key = base64.b64decode(request.COOKIES[constants.SESSION_COOKIE_NAME])
            elif 'HTTP_X_SESSION_KEY' in request.META:
                session_key = base64.b64decode(request.META['HTTP_X_SESSION_KEY'])
            else:
                session_key = None

            # We can't encrypt secret plaintext without a session key.
            if self.action in ['create', 'update'] and session_key is None:
                raise ValidationError("A session key must be provided when creating or updating secrets.")

            # Attempt to retrieve the master key for encryption/decryption if a session key has been provided.
            if session_key is not None:
                try:
                    sk = models.SessionKey.objects.get(userkey__user=request.user)
                    self.master_key = sk.get_master_key(session_key)
                except (models.SessionKey.DoesNotExist, exceptions.InvalidKey):
                    raise ValidationError("Invalid session key.")

    def retrieve(self, request, *args, **kwargs):
        secret = self.get_object()

        # Attempt to decrypt the secret if the master key is known
        if self.master_key is not None:
            secret.decrypt(self.master_key)

        serializer = self.get_serializer(secret)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            # Attempt to decrypt all secrets if the master key is known
            if self.master_key is not None:
                secrets = []
                for secret in page:
                    secret.decrypt(self.master_key)
                    secrets.append(secret)
                serializer = self.get_serializer(secrets, many=True)
            else:
                serializer = self.get_serializer(page, many=True)

            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


#
# Session Keys
#
class SessionKeyViewSet(
    drf_mixins.ListModelMixin,
    drf_mixins.RetrieveModelMixin,
    drf_mixins.DestroyModelMixin,
    mixins.BulkDestroyModelMixin,
    mixins.ObjectValidationMixin,
    BaseViewSet,
):
    queryset = models.SessionKey.objects.prefetch_related('userkey__user')
    serializer_class = serializers.SessionKeySerializer

    def get_queryset(self):
        if self.request.user.is_authenticated:
            # Overrides self.queryset to always return the restricted key filtered by the request.user
            self.queryset = super().get_queryset().filter(userkey__user=self.request.user)
            return self.queryset

        return super().get_queryset()

    @drf_utils.extend_schema(
        request=serializers.SessionKeyCreateSerializer,
        responses={
            201: drf_utils.OpenApiResponse(
                description="Session key created successfully.",
                response=serializers.SessionKeySerializer,
            ),
            400: drf_utils.OpenApiResponse(
                description="Session key creation failed.",
                response={
                    'type': 'string',
                },
                examples=[
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_MISSING, value=ERR_PRIVKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_MISSING, value=ERR_USERKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_INACTIVE, value=ERR_USERKEY_INACTIVE),
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_INVALID, value=ERR_PRIVKEY_INVALID),
                ],
            ),
        },
    )
    def create(self, request):
        """
        Creates a new session key for the current user.
        """

        private_key = request.data.get('private_key', None)
        preserve_key = str(request.data.get('preserve_key', False)).lower() in ['true', 'yes', '1']

        if private_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_MISSING)

        # Validate user key
        try:
            user_key = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)
        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        current_session_key = self.queryset.first()

        if current_session_key and preserve_key:
            # Retrieve the existing session key
            key = current_session_key.get_session_key(master_key)
            self.queryset = current_session_key

        else:
            # Create a new SessionKey
            self.queryset.delete()
            sk = models.SessionKey(userkey=user_key)
            sk.save(master_key=master_key)
            key = sk.key
            self.queryset = sk

        # Encode the key using base64. (b64decode() returns a bytestring under Python 3.)
        encoded_key = base64.b64encode(key).decode()

        # Craft the response
        response = Response(
            self.serializer_class(
                self.queryset,
                context={'request': request, 'session_key': encoded_key},
            ).data,
            status=200 if preserve_key else 201,
        )

        # If token authentication is not in use, assign the session key as a cookie
        if request.auth is None:
            response.set_cookie(
                constants.SESSION_COOKIE_NAME,
                value=encoded_key,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Strict',
                max_age=settings.LOGIN_TIMEOUT,
            )

        return response


class GenerateRSAKeyPairViewSet(ViewSet):
    """
    This endpoint can be used to generate a new RSA key pair. The keys are returned in PEM format.

        {
            "public_key": "<public key>",
            "private_key": "<private key>"
        }
    """

    serializer_class = serializers.RSAKeyPairSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # This is only used to generate the schema
        return models.UserKey.objects.filter(user=self.request.user)

    def list(self, request):
        # Determine what size key to generate
        try:
            key_size = request.GET.get('key_size', public_key_size)
            key_size = int(key_size)
        except ValueError:
            key_size = public_key_size

        if key_size not in range(2048, 8193, 256):
            key_size = public_key_size

        # Export RSA private and public keys in PEM format
        key = RSA.generate(key_size)
        private_key = key.exportKey('PEM')
        public_key = key.publickey().exportKey('PEM')

        return Response(
            {
                'private_key': private_key,
                'public_key': public_key,
            },
        )


class GetSessionKeyViewSet(ViewSet):
    """
    Retrieve a temporary session key to use for encrypting and decrypting secrets via the API. The user's private RSA
    key is POSTed with the name `private_key`.
    This endpoint accepts one optional parameter: `preserve_key`. If True and a session key exists, the existing session
    key will be returned instead of a new one.

    Deprecation notice: This endpoint is deprecated and will be removed in a future release. Use the `SessionKeyViewSet`.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def create(self, request):
        # Read private key
        private_key = request.data.get('private_key', None)
        if private_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_MISSING)

        # Validate user key
        try:
            user_key = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)
        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        try:
            current_session_key = models.SessionKey.objects.get(userkey__user_id=request.user.pk)
        except models.SessionKey.DoesNotExist:
            current_session_key = None

        if current_session_key and request.data.get('preserve_key', False):
            # Retrieve the existing session key
            key = current_session_key.get_session_key(master_key)

        else:
            # Create a new SessionKey
            models.SessionKey.objects.filter(userkey__user=request.user).delete()
            sk = models.SessionKey(userkey=user_key)
            sk.save(master_key=master_key)
            key = sk.key

        # Encode the key using base64. (b64decode() returns a bytestring under Python 3.)
        encoded_key = base64.b64encode(key).decode()

        # Craft the response
        response = Response(
            {
                'session_key': encoded_key,
            },
        )

        # If token authentication is not in use, assign the session key as a cookie
        if request.auth is None:
            response.set_cookie('session_key', value=encoded_key)

        return response


class ActivateUserKeyViewSet(ViewSet):
    """
    This endpoint expects a private key and a list of user keys to be activated.
    The private key is used to derive a master key, which is then used to activate
    each user key provided.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.ActivateUserKeySerializer
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    @drf_utils.extend_schema(
        request=serializers.ActivateUserKeySerializer,
        responses={
            200: drf_utils.OpenApiResponse(
                description="User keys activated successfully.",
                response={
                    'type': 'string',
                },
            ),
            400: drf_utils.OpenApiResponse(
                description="User key activation failed.",
                response={
                    'type': 'string',
                },
                examples=[
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_MISSING, value=ERR_PRIVKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_MISSING, value=ERR_USERKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_INACTIVE, value=ERR_USERKEY_INACTIVE),
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_INVALID, value=ERR_PRIVKEY_INVALID),
                ],
            ),
        },
    )
    def create(self, request):
        # Check if the user has the permission to change UserKey
        if not request.user.has_perm('netbox_secrets.change_userkey'):
            raise PermissionDenied("You do not have permission to active User Keys.")

        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        private_key = serializer.validated_data['private_key']
        user_keys = serializer.validated_data['user_keys']

        # Validate user key
        try:
            user_key = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)

        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        activated_keys = 0
        for key_data in user_keys:
            try:
                user_key = models.UserKey.objects.get(pk=key_data)
                user_key.activate(master_key)
                activated_keys += 1
            except models.UserKey.DoesNotExist:
                return HttpResponseBadRequest(f"User key with id {key_data} does not exist.")

        return Response(f"Successfully activated {activated_keys} user keys.", status=status.HTTP_200_OK)


#
# Zero-Knowledge Tenant Crypto Models
#

class TenantMembershipViewSet(NetBoxModelViewSet):
    """
    ViewSet for managing TenantMembership - links users to tenants with encrypted keys.

    All cryptographic operations happen client-side. The server only stores:
    - encrypted_private_key: User's X25519 private key, encrypted with WebAuthn PRF
    - encrypted_tenant_key: Tenant key encrypted with user's X25519 public key
    """
    queryset = models.TenantMembership.objects.all()
    serializer_class = serializers.TenantMembershipSerializer
    filterset_class = filtersets.TenantMembershipFilterSet

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return serializers.TenantMembershipCreateSerializer
        return serializers.TenantMembershipSerializer

    def get_queryset(self):
        """Filter to only show memberships the user can access."""
        qs = super().get_queryset()
        if self.request.user.is_superuser:
            return qs
        # Users can only see memberships for tenants they are members of
        user_tenants = models.TenantMembership.objects.filter(
            user=self.request.user
        ).values_list('tenant_id', flat=True)
        return qs.filter(tenant_id__in=user_tenants)

    @action(detail=False, methods=['get'])
    def my_memberships(self, request):
        """Get the current user's memberships."""
        memberships = self.queryset.filter(user=request.user)
        serializer = self.get_serializer(memberships, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def encrypted_keys(self, request, pk=None):
        """Get encrypted keys for a membership (for decryption in browser)."""
        membership = self.get_object()
        if membership.user != request.user:
            raise PermissionDenied("You can only access your own encrypted keys.")
        return Response({
            'encrypted_private_key': base64.b64encode(bytes(membership.encrypted_private_key)).decode(),
            'encrypted_tenant_key': base64.b64encode(bytes(membership.encrypted_tenant_key)).decode(),
            'public_key': membership.public_key,
            'webauthn_credential_id': membership.webauthn_credential_id,
        })


class TenantServiceAccountViewSet(NetBoxModelViewSet):
    """
    ViewSet for managing TenantServiceAccount.

    Service accounts require human activation after each restart.
    The activation key is stored ONLY in memory.
    """
    queryset = models.TenantServiceAccount.objects.all()
    serializer_class = serializers.TenantServiceAccountSerializer
    filterset_class = filtersets.TenantServiceAccountFilterSet

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return serializers.TenantServiceAccountCreateSerializer
        return serializers.TenantServiceAccountSerializer

    def get_queryset(self):
        """Filter to only show service accounts for tenants the user can access."""
        qs = super().get_queryset()
        if self.request.user.is_superuser:
            return qs
        user_tenants = models.TenantMembership.objects.filter(
            user=self.request.user
        ).values_list('tenant_id', flat=True)
        return qs.filter(tenant_id__in=user_tenants)

    @action(detail=True, methods=['get'])
    def activation_data(self, request, pk=None):
        """Get data needed for activation (encrypted private key, nonce, salt)."""
        sa = self.get_object()
        # Check user is admin of this tenant
        membership = models.TenantMembership.objects.filter(
            user=request.user,
            tenant=sa.tenant,
            role=models.TenantMembership.ROLE_ADMIN
        ).first()
        if not membership and not request.user.is_superuser:
            raise PermissionDenied("Only tenant admins can activate service accounts.")

        return Response({
            'id': sa.id,
            'name': sa.name,
            'tenant': sa.tenant.name,
            'encrypted_private_key': base64.b64encode(bytes(sa.encrypted_private_key)).decode(),
            'private_key_nonce': base64.b64encode(bytes(sa.private_key_nonce)).decode(),
            'activation_salt': base64.b64encode(bytes(sa.activation_salt)).decode(),
            'is_active': sa.is_active,
        })


class ServiceAccountActivationViewSet(ViewSet):
    """
    ViewSet for activating/deactivating service accounts.

    Activation stores the decrypted private key in memory (lost on restart).
    """
    permission_classes = [IsAuthenticated]
    serializer_class = serializers.TenantServiceAccountActivateSerializer

    @drf_utils.extend_schema(
        request=serializers.TenantServiceAccountActivateSerializer,
        responses={200: {'type': 'object', 'properties': {'status': {'type': 'string'}}}}
    )
    def create(self, request):
        """Activate a service account."""
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        sa_id = serializer.validated_data['service_account_id']
        private_key = serializer.validated_data['decrypted_private_key']

        try:
            sa = models.TenantServiceAccount.objects.get(pk=sa_id)
        except models.TenantServiceAccount.DoesNotExist:
            return Response({'error': 'Service account not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user is admin of this tenant
        membership = models.TenantMembership.objects.filter(
            user=request.user,
            tenant=sa.tenant,
            role=models.TenantMembership.ROLE_ADMIN
        ).first()
        if not membership and not request.user.is_superuser:
            raise PermissionDenied("Only tenant admins can activate service accounts.")

        if not sa.enabled:
            return Response({'error': 'Service account is disabled'}, status=status.HTTP_400_BAD_REQUEST)

        # Store the key in memory
        ServiceAccountActivation.activate(sa_id, private_key, request.user.id)

        return Response({
            'status': 'activated',
            'service_account': sa.name,
            'tenant': sa.tenant.name,
        })

    @action(detail=False, methods=['post'])
    def deactivate(self, request):
        """Deactivate a service account."""
        sa_id = request.data.get('service_account_id')
        if not sa_id:
            return Response({'error': 'service_account_id required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            sa = models.TenantServiceAccount.objects.get(pk=sa_id)
        except models.TenantServiceAccount.DoesNotExist:
            return Response({'error': 'Service account not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user is admin of this tenant
        membership = models.TenantMembership.objects.filter(
            user=request.user,
            tenant=sa.tenant,
            role=models.TenantMembership.ROLE_ADMIN
        ).first()
        if not membership and not request.user.is_superuser:
            raise PermissionDenied("Only tenant admins can deactivate service accounts.")

        ServiceAccountActivation.deactivate(sa_id)
        return Response({'status': 'deactivated'})

    @action(detail=False, methods=['get'])
    def status(self, request):
        """Get activation status of all service accounts."""
        activated_ids = ServiceAccountActivation.get_all_activated_ids()
        return Response({
            'activated_count': len(activated_ids),
            'activated_ids': activated_ids,
        })


class TenantSecretViewSet(NetBoxModelViewSet):
    """
    ViewSet for managing TenantSecret.

    IMPORTANT: The server NEVER sees plaintext. All encryption/decryption
    happens client-side. This endpoint only stores/retrieves ciphertext.
    """
    queryset = models.TenantSecret.objects.all()
    serializer_class = serializers.TenantSecretSerializer
    filterset_class = filtersets.TenantSecretFilterSet

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return serializers.TenantSecretCreateSerializer
        return serializers.TenantSecretSerializer

    def get_queryset(self):
        """Filter to only show secrets for tenants the user can access."""
        qs = super().get_queryset()
        if self.request.user.is_superuser:
            # Superusers can see all secrets BUT cannot decrypt them
            return qs

        user_tenants = models.TenantMembership.objects.filter(
            user=self.request.user
        ).values_list('tenant_id', flat=True)
        return qs.filter(tenant_id__in=user_tenants)

    def retrieve(self, request, *args, **kwargs):
        """Get a secret and record access."""
        secret = self.get_object()
        secret.record_access(request.user)
        serializer = self.get_serializer(secret)
        return Response(serializer.data)


class ServiceAccountSecretViewSet(ViewSet):
    """
    API for service accounts to retrieve secrets.

    Authentication: Bearer token (service account token)
    """
    permission_classes = []  # Custom auth via token

    def _authenticate_service_account(self, request):
        """Authenticate request using service account token."""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header[7:]  # Remove 'Bearer ' prefix
        try:
            sa = models.TenantServiceAccount.objects.get(token=token, enabled=True)
            # Update last used timestamp
            from django.utils import timezone
            sa.token_last_used = timezone.now()
            sa.save(update_fields=['token_last_used'])
            return sa
        except models.TenantServiceAccount.DoesNotExist:
            return None

    def list(self, request):
        """List secrets available to this service account."""
        sa = self._authenticate_service_account(request)
        if not sa:
            return Response({'error': 'Invalid or missing token'}, status=status.HTTP_401_UNAUTHORIZED)

        if not sa.is_active:
            return Response(
                {'error': 'Service account not activated. A human must activate it first.'},
                status=status.HTTP_403_FORBIDDEN
            )

        secrets = models.TenantSecret.objects.filter(tenant=sa.tenant)
        # Return only metadata, not ciphertext (for listing)
        data = [{
            'id': s.id,
            'name': s.name,
            'description': s.description,
            'has_totp': s.has_totp,
        } for s in secrets]
        return Response(data)

    def retrieve(self, request, pk=None):
        """
        Retrieve a secret for decryption by service account.

        Returns:
        - encrypted_tenant_key: Encrypted with service account's X25519 public key
        - ciphertext: AES-256-GCM encrypted secret

        The service account uses its private key (from memory via ServiceAccountActivation)
        to decrypt the tenant key, then decrypts the secret.
        """
        sa = self._authenticate_service_account(request)
        if not sa:
            return Response({'error': 'Invalid or missing token'}, status=status.HTTP_401_UNAUTHORIZED)

        if not sa.is_active:
            return Response(
                {'error': 'Service account not activated. A human must activate it first.'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            secret = models.TenantSecret.objects.get(pk=pk, tenant=sa.tenant)
        except models.TenantSecret.DoesNotExist:
            return Response({'error': 'Secret not found'}, status=status.HTTP_404_NOT_FOUND)

        secret.record_access()

        return Response({
            'id': secret.id,
            'name': secret.name,
            'ciphertext': base64.b64encode(bytes(secret.ciphertext)).decode(),
            'encrypted_tenant_key': base64.b64encode(bytes(sa.encrypted_tenant_key)).decode(),
            'has_totp': secret.has_totp,
            'totp_ciphertext': base64.b64encode(bytes(secret.totp_ciphertext)).decode() if secret.totp_ciphertext else None,
        })

    @action(detail=True, methods=['post'])
    def decrypt(self, request, pk=None):
        """
        Server-side decryption for service accounts.

        This endpoint performs decryption ON THE SERVER using the in-memory
        private key. Use this only if you trust the server and need plaintext.

        For maximum security, retrieve ciphertext and decrypt client-side instead.
        """
        sa = self._authenticate_service_account(request)
        if not sa:
            return Response({'error': 'Invalid or missing token'}, status=status.HTTP_401_UNAUTHORIZED)

        if not sa.is_active:
            return Response(
                {'error': 'Service account not activated'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            secret = models.TenantSecret.objects.get(pk=pk, tenant=sa.tenant)
        except models.TenantSecret.DoesNotExist:
            return Response({'error': 'Secret not found'}, status=status.HTTP_404_NOT_FOUND)

        # Get private key from memory
        private_key = ServiceAccountActivation.get_private_key(sa.id)
        if not private_key:
            return Response(
                {'error': 'Service account activation expired'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Perform decryption server-side
        try:
            from nacl.public import PrivateKey, SealedBox

            # Decrypt tenant key using service account's private key
            priv_key = PrivateKey(private_key)
            sealed_box = SealedBox(priv_key)
            tenant_key = sealed_box.decrypt(bytes(sa.encrypted_tenant_key))

            # Decrypt secret using tenant key (AES-256-GCM)
            from Crypto.Cipher import AES
            ciphertext = bytes(secret.ciphertext)
            nonce = ciphertext[:12]
            encrypted = ciphertext[12:]
            cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(encrypted[:-16], encrypted[-16:])

            secret.record_access()

            result = {
                'id': secret.id,
                'name': secret.name,
                'plaintext': plaintext.decode('utf-8'),
            }

            # Decrypt TOTP if present
            if secret.totp_ciphertext:
                totp_ciphertext = bytes(secret.totp_ciphertext)
                totp_nonce = totp_ciphertext[:12]
                totp_encrypted = totp_ciphertext[12:]
                totp_cipher = AES.new(tenant_key, AES.MODE_GCM, nonce=totp_nonce)
                totp_plaintext = totp_cipher.decrypt_and_verify(totp_encrypted[:-16], totp_encrypted[-16:])
                result['totp_seed'] = totp_plaintext.decode('utf-8')

                # Generate current TOTP code
                import pyotp
                totp = pyotp.TOTP(
                    result['totp_seed'],
                    digits=secret.totp_digits,
                    interval=secret.totp_period,
                )
                result['totp_code'] = totp.now()

            return Response(result)

        except Exception as e:
            return Response({'error': f'Decryption failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
