# Working with Secrets

As with most other objects, the REST API can be used to view, create, modify, and delete secrets. However, additional
steps are needed to encrypt or decrypt secret data.

## Generating a Session Key

In order to encrypt or decrypt secret data, a session key must be attached to the API request. To generate a session key,
send an authenticated request to the `/api/plugins/secrets/session-keys/` endpoint with the private RSA key which
matches your [UserKey](../models/userkey.md). Place the private RSA key in a json file.

```no-highlight
$ curl -X POST http://netbox/api/plugins/secrets/session-keys/ \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4" \
-H "Content-Type: application/json" \
--data @<filename>
```

```json
{
    "pk": 7,
    "id": 7,
    "url": "http://172.16.14.63:8000/api/plugins/secrets/session-keys/7/",
    "display": "admin (RSA)",
    "userkey": {
        "id": 1,
        "url": "http://172.16.14.63:8000/api/plugins/secrets/user-keys/1/",
        "display": "admin"
    },
    "session_key": "4H8MCOl98qom7Ug5fQTzsFcH600SRWxe7KlUyIYxJ+A=",
    "created": "2023-05-07T20:29:38.089884Z"
}
```

!!! note
    To read the private key from a file, use the convention above. Alternatively, the private key can be read from an
environment variable using `--data "{\"private_key\": \"$PRIVATEKEY\"}"`. Converting your private key from PEM RSA to
json works like this:

```
jq -sR . <filename>
```

The request uses the provided private key to unlock your stored copy of the master key and generate a temporary
session key, which can be attached in the `X-Session-Key` header of future API requests.

## Retrieving Secrets

A session key is not needed to retrieve unencrypted secrets: The secret is returned like any normal object with its
`plaintext` field set to null.

```no-highlight
$ curl http://netbox/api/plugins/secrets/secrets/2587/ \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4"
```

```json
{
    "id": 2587,
    "url": "http://netbox/api/plugins/secrets/secrets/2587/",
    "display": "admin",
    "assigned_object_type": "dcim.device",
    "assigned_object_id": 1827,
    "assigned_object": {
        "id": 1827,
        "url": "http://netbox/api/dcim/devices/1827/",
        "display": "MyTestDevice",
        "name": "MyTestDevice"
    },
    "role": {
        "id": 4,
        "url": "http://netbox/api/plugins/secrets/secret-roles/4/",
        "display": "Login Credentials",
        "name": "Login Credentials",
        "slug": "login-creds"
    },
    "name": "admin",
    "plaintext": null,
    "hash": "pbkdf2_sha256$1000$G6mMFe4FetZQ$f+0itZbAoUqW5pd8+NH8W5rdp/2QNLIBb+LGdt4OSKA=",
    "tags": [],
    "custom_fields": {},
    "created": "2022-12-30T21:25:17.335575Z",
    "last_updated": "2022-12-30T21:25:17.335619Z"
}
```

To decrypt a secret, we must include our session key in the `X-Session-Key` header when sending the `GET` request:

```no-highlight
$ curl http://netbox/api/plugins/secrets/secrets/secrets/2587/ \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4" \
-H "X-Session-Key: dyEnxlc9lnGzaOAV1dV/xqYPV63njIbdZYOgnAlGPHk="
```

```json
{
    "id": 2587,
    "url": "http://netbox/api/plugins/secrets/secrets/2587/",
    "display": "admin",
    "assigned_object_type": "dcim.device",
    "assigned_object_id": 1827,
    "assigned_object": {
        "id": 1827,
        "url": "http://netbox/api/dcim/devices/1827/",
        "display": "MyTestDevice",
        "name": "MyTestDevice"
    },
    "role": {
        "id": 4,
        "url": "http://netbox/api/plugins/secrets/secret-roles/4/",
        "display": "Login Credentials",
        "name": "Login Credentials",
        "slug": "login-creds"
    },
    "name": "admin",
    "plaintext": null,
    "hash": "pbkdf2_sha256$1000$G6mMFe4FetZQ$f+0itZbAoUqW5pd8+NH8W5rdp/2QNLIBb+LGdt4OSKA=",
    "tags": [],
    "custom_fields": {},
    "created": "2022-12-30T21:25:17.335575Z",
    "last_updated": "2022-12-30T21:25:17.335619Z"
}
```

Multiple secrets within a list can be decrypted in this manner as well:

```no-highlight
$ curl http://netbox/api/plugins/secrets/secrets/secrets/?limit=3 \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4" \
-H "X-Session-Key: dyEnxlc9lnGzaOAV1dV/xqYPV63njIbdZYOgnAlGPHk="
```

```json
{
    "count": 3482,
    "next": "http://netbox/api/plugins/secrets/secrets/secrets/?limit=3&offset=3",
    "previous": null,
    "results": [
        {
            "id": 2587,
            "plaintext": "foobar",
            ...
        },
        {
            "id": 2588,
            "plaintext": "MyP@ssw0rd!",
            ...
        },
        {
            "id": 2589,
            "plaintext": "AnotherSecret!",
            ...
        },
    ]
}
```

To get a list of secrets from the assigned object

```no-highlight
$ curl http://netbox/api/plugins/secrets/secrets/secrets/?assigned_object_type=dcim.device&assigned_object_id=103 \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4" \
-H "X-Session-Key: dyEnxlc9lnGzaOAV1dV/xqYPV63njIbdZYOgnAlGPHk="
```

```json
{
    "count": 2,
    "next": "http://netbox/api/plugins/secrets/secrets/secrets/?limit=3&offset=3",
    "previous": null,
    "results": [...]
}
```

## Creating and Updating Secrets

Session keys are required when creating or modifying secrets. The secret's `plaintext` attribute is set to its
non-encrypted value, and NetBox uses the session key to compute and store the encrypted value.

```no-highlight
$ curl -X POST http://netbox/api/secrets/secrets/ \
-H "Content-Type: application/json" \
-H "Authorization: Token $TOKEN" \
-H "Accept: application/json; indent=4" \
-H "X-Session-Key: dyEnxlc9lnGzaOAV1dV/xqYPV63njIbdZYOgnAlGPHk=" \
--data '{"assigned_object_id": 1827, "assigned_object_type": "dcim.device", "role": 1, "name": "backup", "plaintext": "Drowssap1"}'
```

```json
{
    "id": 6194,
    "url": "http://netbox/api/plugins/secrets/secrets/9194/",
    "display": "admin",
    "assigned_object_type": "dcim.device",
    "assigned_object_id": 1827,
    "assigned_object": {
        "id": 1827,
        "url": "http://netbox/api/dcim/devices/1827/",
        "display": "device43",
        "name": "device43"
    },
    "role": {
        "id": 4,
        "url": "http://netbox/api/plugins/secrets/secret-roles/4/",
        "display": "Login Credentials",
        "name": "Login Credentials",
        "slug": "login-creds"
    },
    "name": "admin",
    "plaintext": null,
    "hash": "pbkdf2_sha256$1000$J9db8sI5vBrd$IK6nFXnFl+K+nR5/KY8RSDxU1skYL8G69T5N3jZxM7c=",
    "tags": [],
    "custom_fields": {},
    "created": "2022-12-30T21:25:17.335575Z",
    "last_updated": "2022-12-30T21:25:17.335619Z"
}
```

!!! note
    Don't forget to include the `Content-Type: application/json` header when making a POST or PATCH request.
