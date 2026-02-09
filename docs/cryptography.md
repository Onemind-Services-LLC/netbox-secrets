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
- The session key itself is not stored in plaintext; a hash is stored for validation.
- The master key is XOR-encrypted with the session key and stored as the session key cipher.

4) **Secrets (AES)**

- Secret plaintext is encrypted using AES-256-CFB with a random IV.
- The plaintext is padded with a length header and random padding before encryption.
- A validation hash of the plaintext is stored to verify decryption integrity.

## Activation Flow

- First User Key: creates and encrypts the master key automatically.
- Additional User Keys: must be activated by a user with an active key. Activation re-encrypts the master key using the
  target user's public key.

## Data at Rest

- User public keys are stored in plaintext.
- Master key and secret values are always stored encrypted.
- Private keys and session keys are never stored in plaintext by the server.
