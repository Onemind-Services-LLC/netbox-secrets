from django.core.exceptions import PermissionDenied

from utilities.querysets import RestrictedQuerySet


class UserKeyQuerySet(RestrictedQuerySet):
    """QuerySet for UserKey model with cryptographic safety guarantees."""

    def active(self):
        """Return keys with valid encrypted master key cipher."""
        return self.filter(master_key_cipher__isnull=False)

    def delete(self):
        """Prevent bulk deletion to protect master key availability.

        Raises:
            PermissionDenied: Always raised to prevent accidental bulk deletion.

        Note:
            Individual deletion via model.delete() is still permitted.
            This only blocks QuerySet.delete() to prevent catastrophic data loss.
        """
        raise PermissionDenied(
            "Bulk deletion disabled for UserKey to prevent master key loss. "
            "Delete individual keys via model instance or admin interface."
        )
