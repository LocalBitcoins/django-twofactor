from binascii import hexlify
from django.test import TestCase
from django.test.utils import override_settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from oath import totp
from .models import UserAuthToken
from .util import encrypt_value


TWOFACTOR_SETTINGS = {
    "AUTHENTICATION_BACKENDS": (
        'django_twofactor.auth_backends.TwoFactorAuthBackend',
    ),
    "SECRET_KEY": "sekrit",
    "TWOFACTOR_TOTP_OPTIONS":  {
            "period": 30,
            "default_token_type": "dec6",
            # Specify drifts for the unlucky scenario where the period ends after
            # the correct seed is calculated but before authenticate is called
            "forward_drift": 2,
            "backward_drift": 2,
    },
    "TWOFACTOR_ENCRYPTION_KEY": ""
}


@override_settings(**TWOFACTOR_SETTINGS)
class TotpTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="user", password="secret")
        UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"),
            type=UserAuthToken.TYPE_TOTP)
        self.correct_code = totp(hexlify("s33d"))

    def test_basic_auth(self):
        """
        Normal login should work if user doesn't have two-factor auth enabled
        """
        UserAuthToken.objects.all().delete()
        user_or_none = authenticate(username="user", password="secret")
        self.assert_(user_or_none is not None)

    def test_twofactor_auth(self):
        user_or_none = authenticate(
            username="user", password="secret", token=self.correct_code)
        self.assert_(user_or_none is not None)

    def test_twofactor_auth_no_token(self):
        user_or_none = authenticate(
            username="user", password="secret")
        self.assert_(user_or_none is None)

    def test_twofactor_auth_wrong_token(self):
        # Bump every digit of the correct token by 1 to create a wrong token.
        # This ensures that the wrong token is different than the correct
        # token, but is in the same format with it.
        wrong_code = "".join([str((int(c) + 1) % 10)
                              for c in self.correct_code])
        user_or_none = authenticate(
            username="user", password="secret", token=wrong_code)
        self.assert_(user_or_none is None)

    def test_twofactor_auth_wrong_password(self):
        user_or_none = authenticate(
            username="user", password="wrong-password", token=self.correct_code)
        self.assert_(user_or_none is None)


@override_settings(**TWOFACTOR_SETTINGS)
class HotpTests(TestCase):
    codes = ["477324", "532070", "160761"]  # hotp(hexlify("s33d"), i)

    def setUp(self):
        self.user = User.objects.create_user(
            username="user", password="secret")
        self.auth_token = UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"),
            type=UserAuthToken.TYPE_HOTP)

    def test_initial_counter(self):
        self.assertEqual(0, self.auth_token.counter)

    def test_check_auth_code(self):
        valid = self.auth_token.check_auth_code(self.codes[0])
        self.assert_(valid)
        self.assertEqual(1, self.auth_token.counter)

    def test_check_auth_code_ahead(self):
        valid = self.auth_token.check_auth_code(self.codes[1])
        self.assert_(not valid)
        self.assertEqual(0, self.auth_token.counter)

    def test_check_auth_code_behind(self):
        self.auth_token.counter = 1
        valid = self.auth_token.check_auth_code(self.codes[0])
        self.assert_(not valid)
        self.assertEqual(1, self.auth_token.counter)

    # TODO: integration tests with authenticate()
