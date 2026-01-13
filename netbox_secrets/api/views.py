import base64
from typing import Optional

from Crypto.PublicKey import RSA
from django.conf import settings
from django.http import HttpResponseBadRequest
from drf_spectacular import utils as drf_utils
from rest_framework import mixins as drf_mixins, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.viewsets import ReadOnlyModelViewSet, ViewSet

from netbox.api.viewsets import BaseViewSet, MPTTLockedMixin, NetBoxModelViewSet, mixins
from netbox_secrets.models import Secret, SecretRole, UserKey
from . import serializers
from .. import constants, exceptions, filtersets, models

# Plugin settings
plugin_settings = settings.PLUGINS_CONFIG.get('netbox_secrets', {})
public_key_size = plugin_settings.get('public_key_size', 2048)

# Error messages
ERR_USERKEY_MISSING = "No UserKey found for the current user."
ERR_USERKEY_INACTIVE = "UserKey has not been activated for decryption."
ERR_PRIVKEY_MISSING = "Private key was not provided."
ERR_PRIVKEY_INVALID = "Invalid private key."
ERR_SESSION_KEY_REQUIRED = "A session key must be provided when creating or updating secrets."
ERR_SESSION_KEY_INVALID = "Invalid session key."


class SecretsRootView(APIRootView):
    """Root view for the Secrets API."""

    def get_view_name(self):
        return 'Secrets'


#
# User Key
#
class UserKeyViewSet(ReadOnlyModelViewSet):
    queryset = UserKey.objects.all()
    serializer_class = serializers.UserKeySerializer
    filterset_class = filtersets.UserKeyFilterSet


#
# Secret Roles
#


class SecretRoleViewSet(MPTTLockedMixin, NetBoxModelViewSet):
    queryset = SecretRole.objects.add_related_count(
        SecretRole.objects.all(),
        Secret,
        'role',
        'secret_count',
        cumulative=True
    )
    serializer_class = serializers.SecretRoleSerializer
    filterset_class = filtersets.SecretRoleFilterSet


#
# Secrets
#


class SecretViewSet(NetBoxModelViewSet):
    queryset = models.Secret.objects.select_related(
        'role',
        'assigned_object_type'
    ).prefetch_related('tags')
    serializer_class = serializers.SecretSerializer
    filterset_class = filtersets.SecretFilterSet

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.master_key: Optional[bytes] = None

    def get_serializer_context(self):
        """Add master key to serializer context for encryption/decryption."""
        context = super().get_serializer_context()
        context['master_key'] = self.master_key
        return context

    def _get_session_key_from_request(self) -> Optional[bytes]:
        """
        Extract and decode session key from request cookies or headers.

        Returns:
            Decoded session key bytes, or None if not provided
        """
        request = self.request

        # Check cookie first
        if constants.SESSION_COOKIE_NAME in request.COOKIES:
            try:
                return base64.b64decode(request.COOKIES[constants.SESSION_COOKIE_NAME])
            except Exception:
                return None

        # Check X-Session-Key header
        if 'HTTP_X_SESSION_KEY' in request.META:
            try:
                return base64.b64decode(request.META['HTTP_X_SESSION_KEY'])
            except Exception:
                return None

        return None

    def _load_master_key(self, session_key: bytes) -> None:
        """
        Load master key using the provided session key.

        Args:
            session_key: Session key bytes

        Raises:
            ValidationError: If session key is invalid
        """
        try:
            sk = models.SessionKey.objects.get(userkey__user=self.request.user)
            self.master_key = sk.get_master_key(session_key)
        except models.SessionKey.DoesNotExist:
            raise ValidationError(ERR_SESSION_KEY_INVALID)
        except exceptions.InvalidKey:
            raise ValidationError(ERR_SESSION_KEY_INVALID)

    def initial(self, request, *args, **kwargs):
        """
        Perform initial request processing and master key loading.

        Raises:
            ValidationError: If session key is required but missing or invalid
        """
        super().initial(request, *args, **kwargs)

        if not request.user.is_authenticated:
            return

        # Extract session key from request
        session_key = self._get_session_key_from_request()

        # Require session key for create/update operations
        if self.action in ['create', 'update', 'partial_update'] and session_key is None:
            raise ValidationError(ERR_SESSION_KEY_REQUIRED)

        # Load master key if session key provided
        if session_key is not None:
            self._load_master_key(session_key)

    def _decrypt_secret(self, secret: models.Secret) -> None:
        """
        Decrypt a secret if master key is available.

        Args:
            secret: Secret instance to decrypt
        """
        if self.master_key is not None:
            try:
                secret.decrypt(self.master_key)
            except Exception:
                # Silently fail decryption - secret remains encrypted
                pass

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a single secret, decrypting if master key is available.

        Returns:
            Response with secret data (decrypted if possible)
        """
        secret = self.get_object()
        self._decrypt_secret(secret)

        serializer = self.get_serializer(secret)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        """
        List secrets, decrypting all if master key is available.

        Returns:
            Response with paginated secret list (decrypted if possible)
        """
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            # Decrypt all secrets in page if master key available
            if self.master_key is not None:
                for secret in page:
                    self._decrypt_secret(secret)

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
    """
        API endpoint for managing session keys.

        Session keys are temporary keys used to encrypt/decrypt secrets during
        a user session. Each user can have only one active session key at a time.
    """

    queryset = models.SessionKey.objects.select_related('userkey__user')
    serializer_class = serializers.SessionKeySerializer

    def get_queryset(self):
        """
        Filter queryset to current user's session keys only.

        Returns:
            Filtered queryset
        """
        queryset = super().get_queryset()

        if self.request.user.is_authenticated:
            return queryset.filter(userkey__user=self.request.user)

        return queryset

    @drf_utils.extend_schema(
        request=serializers.SessionKeyCreateSerializer,
        responses={
            201: serializers.SessionKeySerializer,
            200: serializers.SessionKeySerializer,
            400: drf_utils.OpenApiResponse(
                description="Session key creation failed",
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
        Create a new session key for the current user.

        Requires the user's private key to derive the master key.
        Optionally preserves an existing session key instead of creating a new one.

        Returns:
            Response with session key (and cookie if not using token auth)
        """
        # Validate input
        private_key = request.data.get('private_key')
        preserve_key = str(request.data.get('preserve_key', False)).lower() in ['true', 'yes', '1']

        if not private_key:
            return HttpResponseBadRequest(ERR_PRIVKEY_MISSING)

        # Validate user key
        try:
            user_key = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)

        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key and get master key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        # Get or create session key
        current_session_key = self.get_queryset().first()

        if current_session_key and preserve_key:
            # Retrieve existing session key
            try:
                key = current_session_key.get_session_key(master_key)
                session_key_obj = current_session_key
                created = False
            except exceptions.InvalidKey:
                return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)
        else:
            # Create new session key
            self.get_queryset().delete()
            session_key_obj = models.SessionKey(userkey=user_key)
            session_key_obj.save(master_key=master_key)
            key = session_key_obj.key
            created = True

        # Encode key as base64
        encoded_key = base64.b64encode(key).decode('utf-8')

        # Build response
        response = Response(
            self.serializer_class(
                session_key_obj,
                context={'request': request, 'session_key': encoded_key},
            ).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

        # Set cookie if not using token authentication
        if request.auth is None:
            response.set_cookie(
                constants.SESSION_COOKIE_NAME,
                value=encoded_key,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Strict',
                max_age=settings.LOGIN_TIMEOUT,
                httponly=True,
            )

        return response


class GenerateRSAKeyPairViewSet(ViewSet):
    """
    API endpoint for generating RSA key pairs.

    Returns a new RSA key pair in PEM format. Key size can be specified
    via the 'key_size' query parameter (default: 2048 bits).
    """

    serializer_class = serializers.RSAKeyPairSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Dummy queryset for schema generation."""
        return models.UserKey.objects.filter(user=self.request.user)

    @drf_utils.extend_schema(
        parameters=[
            drf_utils.OpenApiParameter(
                name='key_size',
                type=int,
                description='RSA key size in bits (2048-8192, increments of 256)',
                default=public_key_size,
            ),
        ],
        responses={200: serializers.RSAKeyPairSerializer},
    )
    def list(self, request):
        """
        Generate a new RSA key pair.

        Query Parameters:
            key_size: Key size in bits (2048-8192, increments of 256)

        Returns:
            Response with public and private keys in PEM format
        """
        # Parse and validate key size
        try:
            key_size = int(request.GET.get('key_size', public_key_size))
        except (ValueError, TypeError):
            key_size = public_key_size

        # Validate key size range (2048-8192, increments of 256)
        if key_size not in range(2048, 8193, 256):
            key_size = public_key_size

        # Generate RSA key pair
        key = RSA.generate(key_size)
        private_key = key.exportKey('PEM').decode('utf-8')
        public_key = key.publickey().exportKey('PEM').decode('utf-8')

        return Response({
            'public_key': public_key,
            'private_key': private_key,
        })


class ActivateUserKeyViewSet(ViewSet):
    """
    API endpoint for activating user keys.

    Allows administrators to activate multiple user keys using their own
    private key to derive the master key. Requires 'change_userkey' permission.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.ActivateUserKeySerializer
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    @drf_utils.extend_schema(
        request=serializers.ActivateUserKeySerializer,
        responses={
            200: drf_utils.OpenApiResponse(
                description="User keys activated successfully",
                examples=[
                    drf_utils.OpenApiExample(
                        name="Success",
                        value="Successfully activated 3 user keys.",
                    ),
                ],
            ),
            400: drf_utils.OpenApiResponse(
                description="User key activation failed",
                examples=[
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_MISSING, value=ERR_PRIVKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_MISSING, value=ERR_USERKEY_MISSING),
                    drf_utils.OpenApiExample(name=ERR_USERKEY_INACTIVE, value=ERR_USERKEY_INACTIVE),
                    drf_utils.OpenApiExample(name=ERR_PRIVKEY_INVALID, value=ERR_PRIVKEY_INVALID),
                ],
            ),
            403: drf_utils.OpenApiResponse(
                description="Permission denied",
            ),
        },
    )
    def create(self, request):
        """
        Activate multiple user keys.

        Requires the administrator's private key to derive the master key,
        which is then used to activate the specified user keys.

        Returns:
            Response indicating how many keys were activated
        """
        # Check permissions
        if not request.user.has_perm('netbox_secrets.change_userkey'):
            raise PermissionDenied("You do not have permission to activate user keys.")

        # Validate input
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        private_key = serializer.validated_data['private_key']
        user_key_ids = serializer.validated_data['user_keys']

        # Validate requesting user's key
        try:
            user_key = models.UserKey.objects.get(user=request.user)
        except models.UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)

        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key and get master key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        # Activate each user key
        activated_count = 0
        failed_keys = []

        for key_id in user_key_ids:
            try:
                target_key = models.UserKey.objects.get(pk=key_id)
                target_key.activate(master_key)
                activated_count += 1
            except models.UserKey.DoesNotExist:
                failed_keys.append(key_id)
            except Exception as e:
                failed_keys.append(key_id)

        # Build response message
        if failed_keys:
            message = (
                f"Activated {activated_count} user keys. "
                f"Failed to activate keys: {', '.join(map(str, failed_keys))}"
            )
            return Response(message, status=status.HTTP_207_MULTI_STATUS)

        return Response(
            f"Successfully activated {activated_count} user keys.",
            status=status.HTTP_200_OK
        )
