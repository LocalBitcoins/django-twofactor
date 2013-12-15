from binascii import hexlify
from django.test import TestCase
from django.test.utils import override_settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from oath import totp
from .models import UserAuthToken
from .util import encrypt_value
from .forms import GridCardActivationForm
from . import auth_forms


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
    "TWOFACTOR_ENCRYPTION_KEY": "",
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


@override_settings(**TWOFACTOR_SETTINGS)
class GridCardActivationFormTests(TestCase):
    codes = ["131779", "404121", "756246"]

    def setUp(self):
        self.user = User.objects.create_user(
            username="user", password="secret")

    def test_grid_card_activation(self):
        data = {
            "key": "brzguxg3uw5",
            "first_code": self.codes[0],
        }
        self._test_activation(data)

    def test_uppercase_is_fine_too(self):
        data = {
            "key": "BRZGUXG3UW5",
            "first_code": self.codes[0],
        }
        self._test_activation(data)

    def _test_activation(self, data):
        form = GridCardActivationForm(self.user, data)
        self.assertTrue(form.is_valid())
        form.save()

        # The HOTP Token should be created
        self.assert_(self.user.userauthtoken)
        self.assertEqual(UserAuthToken.TYPE_HOTP, self.user.userauthtoken.type)

        # Login should work with the second code
        self.assertEqual(1, self.user.userauthtoken.counter)
        user_or_none = authenticate(
            username="user", password="secret", token=self.codes[1])
        self.assertEqual(self.user, user_or_none)

    def test_invalid_checksum(self):
        data = {
            "key": "brzguxg3uw6",
            "first_code": self.codes[0],
        }

        form = GridCardActivationForm(self.user, data)
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid key", form.errors["key"])

    def test_invalid_length(self):
        data = {
            "key": "a0",
            "first_code": self.codes[0],
        }

        form = GridCardActivationForm(self.user, data)
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid key", form.errors["key"])

    def test_invalid_first_code(self):
        data = {
            "key": "brzguxg3uw5",
            "first_code": "123456",
        }

        form = GridCardActivationForm(self.user, data)
        self.assertFalse(form.is_valid())
        self.assertIn("Invalid first code", form.errors["first_code"])


@override_settings(**TWOFACTOR_SETTINGS)
class AuthFormTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="user", password="secret")
        UserAuthToken.objects.create(
            user=self.user,
            type=UserAuthToken.TYPE_HOTP,
            encrypted_seed=encrypt_value("a"),
            counter=20)  # get_hotp("a", 20) = "022728"

    def test_token_starting_with_zero_basic_form(self):
        self._test_token_starting_with_zero(
                auth_forms.TwoFactorAuthenticationForm)

    def test_token_starting_with_zero_admin_form(self):
        self._test_token_starting_with_zero(
                auth_forms.TwoFactorAdminAuthenticationForm,
                extra_data={"this_is_the_login_form": "1"})

    def _test_token_starting_with_zero(self, form_cls, extra_data=None):
        data = {
            "username": "user",
            "password": "secret",
            "token": "022728",
        }
        if extra_data:
            data.update(extra_data)
        form = form_cls(data=data)
        self.assertTrue(form.is_valid(), form.errors)


@override_settings(**TWOFACTOR_SETTINGS)
class SignalsTests(TestCase):
    def test_remove_hotp_token_after_max_logins(self):
        from .models import HOTP_MAX_COUNTER
        from .util import get_hotp
        user = User.objects.create_user(
            username="user", password="secret")
        UserAuthToken.objects.create(
            user=user,
            type=UserAuthToken.TYPE_HOTP,
            encrypted_seed=encrypt_value("a"),
            counter=(HOTP_MAX_COUNTER - 2))
        correct_token_1 = get_hotp("a", HOTP_MAX_COUNTER - 2)
        correct_token_2 = get_hotp("a", HOTP_MAX_COUNTER - 1)

        # Shouldn't be deleted
        user_or_none = authenticate(
                username="user", password="secret", token=correct_token_1)
        self.assertEqual(user, user_or_none)
        self.assertTrue(UserAuthToken.objects.filter(user=user).exists())

        # Should be deleted
        user_or_none = authenticate(
                username="user", password="secret", token=correct_token_2)
        self.assertEqual(user, user_or_none)
        self.assertFalse(UserAuthToken.objects.filter(user=user).exists())
