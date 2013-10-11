from binascii import hexlify
from django.test import TestCase
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from oath import totp
from .models import UserAuthToken
from .util import encrypt_value


class TotpTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="user", password="secret")

    def test_basic_auth(self):
        """
        Normal login should work if user doesn't have two-factor auth enabled
        """
        user_or_none = authenticate(username="user", password="secret")
        self.assert_(user_or_none is not None)

    def test_twofactor_auth(self):
        UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"))
        token = totp(hexlify("s33d"))
        user_or_none = authenticate(
            username="user", password="secret", token=token)

        self.assert_(user_or_none is not None)

    def test_twofactor_auth_no_token(self):
        UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"))
        user_or_none = authenticate(
            username="user", password="secret")

        self.assert_(user_or_none is None)

    def test_twofactor_auth_wrong_token(self):
        UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"))
        correct_token = totp(hexlify("s33d"))
        # Bump every digit of the correct token by 1 to create a wrong token.
        # This ensures that the wrong token is different than the correct
        # token, but is in the same format with it.
        wrong_token = "".join([str((int(c) + 1) % 10)
                               for c in correct_token])
        user_or_none = authenticate(
            username="user", password="secret", token=wrong_token)

        self.assert_(user_or_none is None)

    def test_twofactor_auth_wrong_password(self):
        UserAuthToken.objects.create(
            user=self.user, encrypted_seed=encrypt_value("s33d"))
        token = totp(hexlify("s33d"))
        user_or_none = authenticate(
            username="user", password="wrong-password", token=token)

        self.assert_(user_or_none is None)
