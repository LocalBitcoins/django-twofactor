from django.core.cache import cache
from django.db import models
from django_twofactor.util import (
    check_raw_seed,
    check_hotp,
    decrypt_value,
    encrypt_value,
    get_hotp,
    get_google_url,
    random_seed,
)
from base64 import b32encode
from socket import gethostname


HOTP_MAX_COUNTER = 100


class UserAuthToken(models.Model):
    TYPE_TOTP = 1
    TYPE_HOTP = 2
    TYPE_CHOICES = (
        (TYPE_TOTP, "Time based (TOTP)"),
        (TYPE_HOTP, "Counter based (HOTP)"),
    )

    user = models.OneToOneField("auth.User")
    encrypted_seed = models.CharField(max_length=120)  # fits 16b salt+40b seed
    type = models.PositiveSmallIntegerField(
        choices=TYPE_CHOICES, default=TYPE_TOTP)

    counter = models.PositiveIntegerField(default=0)  # for HOTP

    created_datetime = models.DateTimeField(
        verbose_name="created", auto_now_add=True)
    updated_datetime = models.DateTimeField(
        verbose_name="last updated", auto_now=True)

    def check_auth_code(self, auth_code):
        if self.type == self.TYPE_TOTP:
            return self._check_auth_code_totp(auth_code)
        else:
            return self._check_auth_code_hotp(auth_code)

    def _check_auth_code_totp(self, auth_code):
        """
        Checks whether `auth_code` is a valid authentication code for this
        user, at the current time. (TOTP)
        """
        # allow only one-time use for one auth code.
        cache_key = "onetimeauth_"+str(self.user.id)+"_"+str(auth_code)
        if cache.get(cache_key):  # has been successfully authenticated with this auth key within last 5 minutes
            return False
        result = check_raw_seed(decrypt_value(self.encrypted_seed), auth_code)
        if result:
            cache.set(cache_key, True, 60*5)
        return result

    def _check_auth_code_hotp(self, auth_code):
        """
        Checks whether `auth_code` is a valid authentication code for this
        user, for the current iteration. (HOTP)
        """
        correct = check_hotp(
            decrypt_value(self.encrypted_seed), auth_code, self.counter)
        if correct:
            self.counter += 1
            self.save()
            if self.counter > HOTP_MAX_COUNTER:
                self.delete()
        return correct

    def reset_seed(self, seed=None):
        """
        Resets seed to `seed` or to a new random seed, and takes care of
        everything that needs to be done after that (e.g. reseting HOTP
        counter). Doesn't save the model.
        """
        if seed is None:
            seed = random_seed(30)
        self.encrypted_seed = encrypt_value(seed)
        self.counter = 0

    def is_totp(self):
        return self.type == self.TYPE_TOTP

    def is_hotp(self):
        return self.type == self.TYPE_HOTP

    def b32_secret(self):
        """
        The base32 version of the seed (for input into Google Authenticator
        and similar soft token devices.
        """
        return b32encode(decrypt_value(self.encrypted_seed))

    def google_url(self, name=None):
        """
        The Google Charts QR code version of the seed, plus an optional
        name for this (defaults to "username@hostname").
        """
        if not name:
            username = self.user.username
            hostname = gethostname()
            name = "%s@%s" % (username, hostname)

        return get_google_url(
            decrypt_value(self.encrypted_seed),
            name,
            "hotp" if self.is_hotp() else "totp"
        )
