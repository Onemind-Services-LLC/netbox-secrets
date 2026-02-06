import base64
import logging
from typing import Optional

from Crypto.PublicKey import RSA
from django.db import transaction
from django.http import HttpResponseBadRequest
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import mixins as drf_mixins, status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.viewsets import GenericViewSet, ViewSet

from netbox.api.viewsets import BaseViewSet, NetBoxModelViewSet, mixins
from netbox_secrets.constants import *
from netbox_secrets.exceptions import InvalidKey
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey
from . import serializers
from .. import filtersets

logger = logging.getLogger(__name__)

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
ERR_NO_KEYS_PROVIDED = "No user key IDs provided."
ERR_NO_SESSION_KEY = "No active session key found"


class SecretsRootView(APIRootView):
    """Root view for the Secrets API."""

    def get_view_name(self):
        return 'Secrets'


#
# User Key
#
class UserKeyViewSet(NetBoxModelViewSet):
    queryset = UserKey.objects.all()
    serializer_class = serializers.UserKeySerializer
    filterset_class = filtersets.UserKeyFilterSet

    @extend_schema(
        summary="Bulk activate user keys",
        description=(
            "Activates multiple user keys using the administrator's private key "
            "to derive the master key. All activations are performed atomically.\n\n"
            "This is a bulk operation and requires the `change_userkey` permission."
        ),
        request=serializers.ActivateUserKeySerializer,
        responses={
            200: OpenApiResponse(
                description="User keys activated successfully",
                examples=[
                    OpenApiExample(
                        name="Success",
                        value={
                            'message': 'Successfully activated 3 user keys.',
                            'activated_count': 3,
                            'activated_keys': [1, 2, 3],
                        },
                    )
                ],
            ),
            400: OpenApiResponse(description="Validation failed"),
            403: OpenApiResponse(description="Permission denied"),
            404: OpenApiResponse(description="One or more user keys not found"),
            500: OpenApiResponse(description="Internal server error"),
        },
    )
    @action(
        detail=False,
        methods=['post'],
        url_path='activate',
        permission_classes=[IsAuthenticated],
    )
    def activate(self, request):
        """
        POST /api/plugins/secrets/user-keys/activate/

        Activate multiple user keys using the administrator's master key.
        """

        # Permission check
        if not request.user.has_perm('netbox_secrets.change_userkey'):
            raise PermissionDenied("You do not have permission to activate user keys.")

        serializer = serializers.ActivateUserKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        private_key = serializer.validated_data['private_key']
        user_key_ids = serializer.validated_data['user_key_ids']

        # Validate requesting user's own key
        try:
            admin_key = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
            return Response({'error': ERR_USERKEY_MISSING}, status=status.HTTP_400_BAD_REQUEST)

        if not admin_key.is_active():
            return Response({'error': ERR_USERKEY_INACTIVE}, status=status.HTTP_400_BAD_REQUEST)

        # Derive master key
        master_key = admin_key.get_master_key(private_key)
        if master_key is None:
            return Response({'error': ERR_PRIVKEY_INVALID}, status=status.HTTP_400_BAD_REQUEST)

        # Perform activation atomically
        try:
            with transaction.atomic():
                activated = []
                keys = UserKey.objects.select_for_update().filter(pk__in=user_key_ids)

                existing_ids = set(keys.values_list('pk', flat=True))
                missing_ids = set(user_key_ids) - existing_ids
                if missing_ids:
                    return Response(
                        {
                            'error': f'The following user key IDs were not found: {", ".join(map(str, missing_ids))}',
                            'invalid_keys': list(missing_ids),
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

                for key in keys:
                    key.activate(master_key)
                    activated.append(key.pk)

                return Response(
                    {
                        'message': f'Successfully activated {len(activated)} user key{"s" if len(activated) != 1 else ""}.',
                        'activated_count': len(activated),
                        'activated_keys': activated,
                    },
                    status=status.HTTP_200_OK,
                )

        except Exception:
            logger.exception("Failed to activate user keys.")
            return Response(
                {
                    'error': 'Failed to activate user keys.',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


#
# Secret Roles
#


class SecretRoleViewSet(NetBoxModelViewSet):
    queryset = SecretRole.objects.add_related_count(
        SecretRole.objects.all(), Secret, 'role', 'secret_count', cumulative=True
    )
    serializer_class = serializers.SecretRoleSerializer
    filterset_class = filtersets.SecretRoleFilterSet


#
# Secrets
#


class SecretViewSet(NetBoxModelViewSet):
    queryset = Secret.objects.select_related('role', 'assigned_object_type').prefetch_related('tags')
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
        if SESSION_COOKIE_NAME in request.COOKIES:
            try:
                return base64.b64decode(request.COOKIES[SESSION_COOKIE_NAME])
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
            sk = SessionKey.objects.get(userkey__user=self.request.user)
            self.master_key = sk.get_master_key(session_key)
        except SessionKey.DoesNotExist:
            raise ValidationError(ERR_SESSION_KEY_INVALID)
        except InvalidKey:
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

    def _decrypt_secret(self, secret: Secret) -> None:
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
class SessionKeyViewSet(GenericViewSet):
    """
    API endpoint for managing session keys.

    Session keys are temporary keys used to encrypt/decrypt secrets during
    a user session. Each user can have only one active session key at a time.

    Endpoints:
        GET - Retrieve current user's session key
        POST - Create new session key
        DELETE - Delete current user's session key
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.SessionKeySerializer
    queryset = SessionKey.objects.select_related('userkey__user')

    def get_queryset(self):
        """
        Filter queryset to current user's session keys only.

        Returns:
            Filtered queryset
        """
        return self.queryset.filter(userkey__user=self.request.user)

    @extend_schema(
        responses={
            200: serializers.SessionKeySerializer,
            404: OpenApiResponse(
                description="No session key found",
                examples=[
                    OpenApiExample(name=ERR_NO_SESSION_KEY, value=ERR_NO_SESSION_KEY),
                ],
            ),
        },
    )
    def list(self, request):
        """
        GET /api/session-key/
        Retrieve the current user's session key details.

        Returns session key metadata (not the actual key value).
        """
        session_key = self.get_queryset().first()

        if not session_key:
            return Response({"detail": ERR_NO_SESSION_KEY}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(session_key)
        return Response(serializer.data)

    @extend_schema(
        request=serializers.SessionKeyCreateSerializer,
        responses={
            201: serializers.SessionKeySerializer,
            200: serializers.SessionKeySerializer,
            400: OpenApiResponse(
                description="Session key creation failed",
                examples=[
                    OpenApiExample(name=ERR_PRIVKEY_MISSING, value=ERR_PRIVKEY_MISSING),
                    OpenApiExample(name=ERR_USERKEY_MISSING, value=ERR_USERKEY_MISSING),
                    OpenApiExample(name=ERR_USERKEY_INACTIVE, value=ERR_USERKEY_INACTIVE),
                    OpenApiExample(name=ERR_PRIVKEY_INVALID, value=ERR_PRIVKEY_INVALID),
                ],
            ),
        },
    )
    def create(self, request):
        """
        POST /api/session-key/
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
            user_key = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
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
            except InvalidKey:
                return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)
        else:
            # Create new session key
            self.get_queryset().delete()
            session_key_obj = SessionKey(userkey=user_key)
            session_key_obj.save(master_key=master_key)
            key = session_key_obj.key
            created = True

        # Encode key as base64
        encoded_key = base64.b64encode(key).decode('utf-8')

        # Build response
        context = self.get_serializer_context()
        context['session_key'] = encoded_key
        serializer = self.get_serializer(session_key_obj, context=context)
        response = Response(
            serializer.data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

        # Set cookie if not using token authentication
        if request.auth is None:
            response.set_cookie(
                SESSION_COOKIE_NAME,
                value=encoded_key,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Strict',
                max_age=settings.LOGIN_TIMEOUT,
                httponly=True,
            )

        return response

    @extend_schema(
        responses={
            204: OpenApiResponse(description="Session key deleted successfully"),
            404: OpenApiResponse(
                description="No session key found",
                examples=[
                    OpenApiExample(name=ERR_NO_SESSION_KEY, value=ERR_NO_SESSION_KEY),
                ],
            ),
        },
    )
    def delete(self, request):
        """
        DELETE /api/session-key/
        Delete the current user's session key.
        """
        session_key = self.get_queryset().first()
        if not session_key:
            response = Response(
                {"detail": ERR_NO_SESSION_KEY},
                status=status.HTTP_404_NOT_FOUND,
            )
        else:
            session_key.delete()
            response = Response(status=status.HTTP_204_NO_CONTENT)

        response.delete_cookie(SESSION_COOKIE_NAME)
        return response


class GenerateRSAKeyPairView(ViewSet):
    """
    Generate RSA key pairs for encryption purposes.

    This endpoint generates a new RSA public/private key pair and returns
    both keys in PEM format. The private key should be stored securely
    and never shared.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Generate RSA Key Pair",
        description=(
            "Generates a new RSA public/private key pair in PEM format. "
            "The key size can be customized via query parameter.\n\n"
            "**Important:** Store the private key securely and never expose it. "
            "Once generated, you cannot retrieve the same key pair again."
        ),
        parameters=[
            OpenApiParameter(
                name='key_size',
                type=OpenApiTypes.INT,
                location='query',
                description=(
                    f'RSA key size in bits. Must be between {MIN_KEY_SIZE} and {MAX_KEY_SIZE} '
                    f'in increments of {KEY_SIZE_INCREMENT}.'
                ),
                default=DEFAULT_KEY_SIZE,
                examples=[
                    OpenApiExample('Default', value=2048, description='Standard key size for most use cases'),
                    OpenApiExample('High Security', value=4096, description='Higher security for sensitive data'),
                ],
            ),
        ],
        responses={
            200: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'public_key': {
                            'type': 'string',
                            'description': 'RSA public key in PEM format',
                            'example': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
                        },
                        'private_key': {
                            'type': 'string',
                            'description': 'RSA private key in PEM format (keep secure!)',
                            'example': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
                        },
                        'key_size': {
                            'type': 'integer',
                            'description': 'The size of the generated key in bits',
                            'example': 2048,
                        },
                    },
                    'required': ['public_key', 'private_key', 'key_size'],
                },
                description='Successfully generated RSA key pair',
            ),
            400: OpenApiResponse(
                response={
                    'type': 'object',
                    'properties': {
                        'error': {
                            'type': 'string',
                            'example': 'Invalid key size. Must be between 2048 and 8192 in increments of 256.',
                        }
                    },
                },
                description='Invalid key size parameter',
            ),
            401: OpenApiResponse(description='Authentication credentials were not provided or are invalid'),
        },
    )
    def list(self, request):
        """Generate and return a new RSA key pair."""

        # Parse and validate key size
        key_size_param = request.query_params.get('key_size', DEFAULT_KEY_SIZE)

        try:
            key_size = int(key_size_param)
        except (ValueError, TypeError):
            return Response({'error': f'Invalid key_size parameter. Must be an integer.'}, status=400)

        # Validate key size is within allowed range and increment
        if key_size < MIN_KEY_SIZE or key_size > MAX_KEY_SIZE:
            return Response(
                {'error': (f'Invalid key size. Must be between {MIN_KEY_SIZE} ' f'and {MAX_KEY_SIZE} bits.')},
                status=400,
            )

        if (key_size - MIN_KEY_SIZE) % KEY_SIZE_INCREMENT != 0:
            return Response(
                {
                    'error': (
                        f'Invalid key size. Must be in increments of {KEY_SIZE_INCREMENT} '
                        f'starting from {MIN_KEY_SIZE}.'
                    )
                },
                status=400,
            )

        # Generate RSA key pair
        try:
            key = RSA.generate(key_size)
            private_key = key.export_key('PEM').decode('utf-8')
            public_key = key.publickey().export_key('PEM').decode('utf-8')
        except Exception:
            logger.exception("Failed to generate RSA key pair.")
            return Response({'error': 'Failed to generate key pair due to an internal error.'}, status=500)

        return Response(
            {
                'public_key': public_key,
                'private_key': private_key,
                'key_size': key_size,
            }
        )


# Legacy support for old viewset style


class LegacySessionKeyViewSet(
    drf_mixins.ListModelMixin,
    drf_mixins.RetrieveModelMixin,
    drf_mixins.DestroyModelMixin,
    mixins.BulkDestroyModelMixin,
    mixins.ObjectValidationMixin,
    BaseViewSet,
):
    queryset = SessionKey.objects.prefetch_related('userkey__user')
    serializer_class = serializers.SessionKeySerializer

    def get_queryset(self):
        if self.request.user.is_authenticated:
            # Overrides self.queryset to always return the restricted key filtered by the request.user
            self.queryset = super().get_queryset().filter(userkey__user=self.request.user)
            return self.queryset

        return super().get_queryset()

    @extend_schema(
        request=serializers.SessionKeyCreateSerializer,
        responses={
            201: OpenApiResponse(
                description="Session key created successfully.",
                response=serializers.SessionKeySerializer,
            ),
            400: OpenApiResponse(
                description="Session key creation failed.",
                response={
                    'type': 'string',
                },
                examples=[
                    OpenApiExample(name=ERR_PRIVKEY_MISSING, value=ERR_PRIVKEY_MISSING),
                    OpenApiExample(name=ERR_USERKEY_MISSING, value=ERR_USERKEY_MISSING),
                    OpenApiExample(name=ERR_USERKEY_INACTIVE, value=ERR_USERKEY_INACTIVE),
                    OpenApiExample(name=ERR_PRIVKEY_INVALID, value=ERR_PRIVKEY_INVALID),
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
            user_key = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
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
            sk = SessionKey(userkey=user_key)
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
                SESSION_COOKIE_NAME,
                value=encoded_key,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite='Strict',
                max_age=settings.LOGIN_TIMEOUT,
            )

        return response


class LegacyActivateUserKeyViewSet(ViewSet):
    """
    Backward-compatible endpoint for /activate-user-key/.

    Deprecated: use /user-keys/activate/ with user_key_ids. This endpoint is kept
    for compatibility and is scheduled for removal when the plugin targets NetBox v4.6.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.ActivateUserKeySerializer

    def create(self, request):
        """
        Activate one or more user keys using the caller's private key.

        Legacy behavior accepts `user_keys` or `user_key_ids` and returns a plain
        success string. The caller must have `netbox_secrets.change_userkey` and
        an active user key to decrypt the master key.
        """
        # Check if the user has the permission to change UserKey
        if not request.user.has_perm('netbox_secrets.change_userkey'):
            raise PermissionDenied("You do not have permission to active User Keys.")

        data = request.data.copy()
        if 'user_keys' in data and 'user_key_ids' not in data:
            data['user_key_ids'] = data.get('user_keys')

        serializer = self.serializer_class(data=data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        private_key = serializer.validated_data['private_key']
        user_key_ids = serializer.validated_data['user_key_ids']

        if not user_key_ids:
            return HttpResponseBadRequest(ERR_NO_KEYS_PROVIDED)

        # Validate user key
        try:
            user_key = UserKey.objects.get(user=request.user)
        except UserKey.DoesNotExist:
            return HttpResponseBadRequest(ERR_USERKEY_MISSING)

        if not user_key.is_active():
            return HttpResponseBadRequest(ERR_USERKEY_INACTIVE)

        # Validate private key
        master_key = user_key.get_master_key(private_key)
        if master_key is None:
            return HttpResponseBadRequest(ERR_PRIVKEY_INVALID)

        activated_keys = 0
        for key_id in user_key_ids:
            try:
                target_key = UserKey.objects.get(pk=key_id)
                target_key.activate(master_key)
                activated_keys += 1
            except UserKey.DoesNotExist:
                return HttpResponseBadRequest(f"User key with id {key_id} does not exist.")

        return Response(f"Successfully activated {activated_keys} user keys.", status=status.HTTP_200_OK)
