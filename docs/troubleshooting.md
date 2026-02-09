# Troubleshooting

## "No UserKey found for the current user"

You must create a User Key for the authenticated user before requesting a session key.

## "UserKey has not been activated"

Your User Key exists but does not yet have an encrypted master key. Ask an administrator with an active key to activate
it.

## "Invalid private key" when requesting a session key

- Ensure the private key matches the public key stored in your User Key.
- Ensure the key is in PEM format and not passphrase-protected.

## Secrets do not appear on an object page

- Confirm the model is listed in `PLUGINS_CONFIG['netbox_secrets']['apps']`.
- Check `display_default` and `display_setting` configuration.

## Cannot delete a User Key

The last active User Key cannot be deleted if secrets exist. Create and activate another key first.

## Session key keeps prompting in the UI

- Make sure your browser allows session storage.
- Request a session key again after page reload.
