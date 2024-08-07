from utilities.querysets import RestrictedQuerySet


class UserKeyQuerySet(RestrictedQuerySet):
    def active(self):
        return self.filter(master_key_cipher__isnull=False)

    def delete(self):
        # Disable bulk deletion to avoid accidentally wiping out all copies of the master key.
        raise Exception("Bulk deletion has been disabled.")
