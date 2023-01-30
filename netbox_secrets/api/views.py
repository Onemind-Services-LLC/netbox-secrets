import base64

from Crypto.PublicKey import RSA
from django.conf import settings
from django.http import HttpResponseBadRequest
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.routers import APIRootView
from rest_framework.viewsets import ModelViewSet, ViewSet
from utilities.utils import count_related

from netbox_secrets import filtersets
from netbox_secrets.exceptions import InvalidKey
from netbox_secrets.models import Secret, SecretRole, SessionKey, UserKey

from . import serializers

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
class UserKeyViewSet(ModelViewSet):
    queryset = UserKey.objects.all()
    serializer_class = serializers.UserKeySerializer

    def get_queryset(self):
        return UserKey.objects.filter(user=self.request.user)


#
# Secret Roles
#


class SecretRoleViewSet(NetBoxModelViewSet):
    queryset = SecretRole.objects.annotate(secret_count=count_related(Secret, 'role')).prefetch_related('tags')
    serializer_class = serializers.SecretRoleSerializer
    filterset_class = filtersets.SecretRoleFilterSet


#
# Secrets
#


class SecretViewSet(NetBoxModelViewSet):
    queryset = Secret.objects.prefetch_related('role', 'tags')
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
            if 'session_key' in request.COOKIES:
                session_key = base64.b64decode(request.COOKIES['session_key'])
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
                    sk = SessionKey.objects.get(userkey__user=request.user)
                    self.master_key = sk.get_master_key(session_key)
                except (SessionKey.DoesNotExist, InvalidKey):
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


class GetSessionKeyViewSet(ViewSet):
    """
    Retrieve a temporary session key to use for encrypting and decrypting secrets via the API. The user's private RSA
    key is POSTed with the name `private_key`.

    This endpoint accepts one optional parameter: `preserve_key`. If True and a session key exists, the existing session
    key will be returned instead of a new one.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['private_key'],
            properties={
                'private_key': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Private RSA key used to decrypt the session key',
                ),
                'preserve_key': openapi.Schema(
                    type=openapi.TYPE_BOOLEAN,
                    description='Preserve existing session key',
                    default=False,
                ),
            },
        ),
    )
    def create(self, request):

        # Read private key
        private_key = request.data.get('private_key', None)
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

        try:
            current_session_key = SessionKey.objects.get(userkey__user_id=request.user.pk)
        except SessionKey.DoesNotExist:
            current_session_key = None

        if current_session_key and request.data.get('preserve_key', False):

            # Retrieve the existing session key
            key = current_session_key.get_session_key(master_key)

        else:

            # Create a new SessionKey
            SessionKey.objects.filter(userkey__user=request.user).delete()
            sk = SessionKey(userkey=user_key)
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


class GenerateRSAKeyPairViewSet(ViewSet):
    """
    This endpoint can be used to generate a new RSA key pair. The keys are returned in PEM format.

        {
            "public_key": "<public key>",
            "private_key": "<private key>"
        }
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='key_size',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='Number of bits in the key',
                default=public_key_size,
            ),
        ],
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                required=['public_key', 'private_key'],
                properties={
                    'public_key': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description='Public RSA key',
                    ),
                    'private_key': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description='Private RSA key',
                    ),
                },
            ),
        },
    )
    def list(self, request):

        # Determine what size key to generate
        try:
            key_size = request.GET.get('key_size', public_key_size)
            key_size = int(key_size)
        except ValueError:
            key_size = public_key_size

        if key_size not in range(2048, 4097, 256):
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
