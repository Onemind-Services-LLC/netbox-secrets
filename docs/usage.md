# Usage Guide

This guide walks through the main workflows in the UI.

## 1) Create a User Key

A User Key stores a user's RSA public key and an encrypted copy of the master key. The private key never leaves the user.

Steps:

1. Go to **Secrets > User Keys**.
2. Click **Add**.
3. Paste your RSA public key, or generate a new key pair from the UI.
4. Save the User Key.

Notes:

- The first active User Key auto-generates the master key for the system.
- Additional User Keys must be activated by a user who already has an active key.
- The UI creates a key for the current user. If you need to create keys for other users, use the REST API with the
  appropriate permissions.

## 2) Activate User Keys (Admin)

If you have `netbox_secrets.change_userkey` permission and an active key, you can activate other users.

1. Go to **Secrets > User Keys**.
2. Click **Activate User Keys**.
3. Select one or more keys and provide your private key.
4. Submit to activate.

## 3) Create a Session Key

A session key is required to encrypt or decrypt secrets.

From the UI:

1. Open the User Key page.
2. Click **Request Session Key**.
3. Paste your RSA private key.

The session key is stored in the browser session and used for subsequent API requests.

## 4) Create a Secret Role

Secret Roles are used to categorize secrets (for example, "Login Credentials" or "API Keys").

1. Go to **Secrets > Secret Roles**.
2. Add a new role.

## 5) Create and View Secrets

1. Navigate to an object (for example, a device).
2. Click **Add Secret**.
3. Fill in the secret details and plaintext.
4. Save.

If you do not have an active session key, the UI prompts you to provide your private key.
