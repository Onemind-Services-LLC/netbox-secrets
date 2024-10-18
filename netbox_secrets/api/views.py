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
from rest_framework.routers import APIRootView
from rest_framework.viewsets import ReadOnlyModelViewSet, ViewSet
from utilities.query import count_related

from . import serializers
from .. import constants, exceptions, filtersets, models

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
