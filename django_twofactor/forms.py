import os
from base64 import b64encode
from django import forms
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django_twofactor.models import UserAuthToken
from django_twofactor import util


TWOFACTOR_PLACE_NAME = getattr(settings, "TWOFACTOR_PLACE_NAME", "TwoFactorTest")


class ResetTwoFactorAuthForm(forms.Form):
    type = forms.TypedChoiceField(
            required=True, coerce=int, choices=UserAuthToken.TYPE_CHOICES)
    reset_confirmation = forms.BooleanField(required=True)

    def __init__(self, user, *args, **kwargs):
        super(ResetTwoFactorAuthForm, self).__init__(*args, **kwargs)
        if user:
            try:
                self.token = UserAuthToken.objects.get(user=user)
                self.fields["type"].initial = self.token.type
            except UserAuthToken.DoesNotExist:
                self.token = UserAuthToken(user=user)
        else:
            self.token = None

    def save(self):
        if not self.token:
            return None

        self.token.type = self.cleaned_data["type"]
        self.token.reset_seed()
        self.token.save()
        return self.token


class DisableTwoFactorAuthForm(forms.Form):
    disable_confirmation = forms.BooleanField(required=True)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(DisableTwoFactorAuthForm, self).__init__(*args, **kwargs)

    def save(self):
        if not self.user:
            return None

        UserAuthToken.objects.filter(user=self.user).delete()

        return self.user


class GridCardActivationForm(forms.Form):
    key = forms.CharField(max_length=11, required=True)
    first_code = forms.CharField(max_length=6, required=True)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(GridCardActivationForm, self).__init__(*args, **kwargs)

    def clean_key(self):
        """Lowercase the key and check that it matches its checksum"""
        key = self.cleaned_data["key"].lower()
        if not util.verify_checksum(key) or len(key) < 11:
            raise forms.ValidationError("Invalid key")
        return key

    def clean(self):
        """Test that the first code is correct"""
        data = super(GridCardActivationForm, self).clean()
        key = data.get("key")
        first_code = data.get("first_code")
        if not (key and first_code):
            return data
        seed = util.key_to_seed(key)
        if first_code != util.get_hotp(seed, 0):
            self._errors["first_code"] = self.error_class(["Invalid first code"])
            del data["first_code"]
        return data

    def save(self):
        try:
            token = UserAuthToken.objects.get(user=self.user)
        except UserAuthToken.DoesNotExist:
            token = UserAuthToken(user=self.user)

        base36_with_checksum = self.cleaned_data["key"]
        seed = util.key_to_seed(base36_with_checksum)
        token.type = UserAuthToken.TYPE_HOTP
        token.reset_seed(seed)
        # Start at the second code
        token.counter = 1
        token.save()


class EnableTwoFactorForm(forms.Form):

    secret_key = forms.CharField(widget=forms.HiddenInput(attrs={'readonly': True}))

    secret_key_b32 = forms.CharField(label=_("Authentication Key"),
        widget=forms.TextInput(attrs={'readonly': True})
    )

    token = forms.IntegerField(label=_("Authentication Code"),
        help_text="Enter the changing six-digit number from your authentication mobile phone or device here. If the code is not accepeted make sure the mobile phone is in correct time.",
        widget=forms.TextInput(attrs={'class': 'input-small', 'maxlength': '6', 'autocomplete': 'off'}),
        min_value=1, max_value=999999,
        required=True
    )

    def __init__(self, user, *args, **kwargs):
        super(EnableTwoFactorForm, self).__init__(*args, **kwargs)
        self.user = user
        if "secret_key" not in self.data:
            self.auth_token = UserAuthToken(user=self.user)
            key = b64encode(os.urandom(16))[:10]
            self.fields['secret_key'].initial = key
            self.auth_token.encrypted_seed = util.encrypt_value(self.fields['secret_key'].initial)
            self.fields['secret_key_b32'].initial = self.auth_token.b32_secret()
        else:
            self.auth_token = UserAuthToken(user=self.user)
            self.auth_token.encrypted_seed = util.encrypt_value(self.data["secret_key"])

    def secret_url(self):
        return self.auth_token.google_url(name=self.user.username + "@" + TWOFACTOR_PLACE_NAME)

    def clean(self):
        if "token" not in self.cleaned_data:
            raise forms.ValidationError(_(u"Please enter the authentication code."))
        if UserAuthToken.objects.filter(user=self.user).count() > 0:
            raise forms.ValidationError(_(u"Two-factor authentication already enabled for this user!"))
        validate = self.auth_token.check_auth_code(self.cleaned_data["token"])
        if (validate == True):
            self.auth_token.save()
        else:
            raise forms.ValidationError(_(u"Invalid authentication code. Please try again."))


class DisableTwoFactorForm(forms.Form):

    def __init__(self, user, *args, **kwargs):
        super(DisableTwoFactorForm, self).__init__(*args, **kwargs)
        self.user = user

    token = forms.IntegerField(label=_("Authentication Code"),
        help_text="Enter the six-digit number from your authentication device here.",
        widget=forms.TextInput(attrs={'class': 'input-small', 'maxlength': '6'}),
        min_value=1, max_value=999999,
        required=False
    )

    def clean(self):
        try:
            auth_token = UserAuthToken.objects.get(user=self.user)
            validate = auth_token.check_auth_code(self.cleaned_data["token"])
            if (validate == True):
                auth_token.delete()
            else:
                raise forms.ValidationError(_(u"Invalid authentication code. Please try again."))
        except UserAuthToken.DoesNotExist:
            raise forms.ValidationError(_(u"Two-factor authentication already disabled!"))
