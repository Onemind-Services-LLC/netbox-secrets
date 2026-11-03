# Cryptography and Key Workflow

This section explains the key hierarchy and how secrets are protected.

## Key Hierarchy

1) **Master Key**

- A random 256-bit master key is generated when the first active User Key is created.
- The master key is never stored in plaintext.

2) **User Keys (RSA)**

- Each user has an RSA key pair.
- Only the public key is stored in NetBox.
- The master key is encrypted for each user using RSA OAEP and stored as `master_key_cipher`.

3) **Session Keys**

- When a user provides their private key, the master key is decrypted and a random 256-bit session key is created.
- The session key is returned to the client (base64).
- The session key itself is not stored in plaintext; a SHA-256 hash is stored for validation. The key is 256 bits of random
  data, so a slow password hash would only add CPU cost to every request without adding security.
- The master key is XOR-encrypted with the session key and stored as the session key cipher.

4) **Secrets (AES)**

- Secret plaintext is encrypted using AES-256-CFB with a random IV.
- The plaintext is padded with a length header and random padding before encryption.
- A validation hash of the plaintext is stored to verify decryption integrity. It is an HMAC-SHA256 keyed with the master
  key, so it is fast to check and cannot be used to guess plaintexts without the master key. Hashes created by older
  releases (PBKDF2) are still accepted for now (see below).

> **Upgrade note, session keys:** session keys created by older releases (slow PBKDF2 hash) are no longer accepted.
> After upgrading, delete your session key and create a new one: `DELETE /api/plugins/secrets/session-key/`, then
> `POST /api/plugins/secrets/session-key/` with your private key (in the UI: delete the session key and enter your
> private key again). Do not use `preserve_key` for this, the old key cannot be preserved.
>
> **Deprecation, secrets:** secrets created by older releases still validate against their legacy (PBKDF2) hash and a
> `DeprecationWarning` is emitted. Support for legacy secret hashes will be removed in NetBox v4.8.

## Activation Flow

- First User Key: creates and encrypts the master key automatically.
- Additional User Keys: must be activated by a user with an active key. Activation re-encrypts the master key using the
  target user's public key.

## Data at Rest

- User public keys are stored in plaintext.
- Master key and secret values are always stored encrypted.
- Private keys and session keys are never stored in plaintext by the server.
