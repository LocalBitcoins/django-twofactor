from django import forms
from django_twofactor.models import UserAuthToken
from django_twofactor import util
from django.utils.translation import ugettext_lazy as _


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


def retrofit_token_field(fields, user_auth_token):
    """ Include two-factor token field on any form.
    """

    fields["token"] = forms.CharField(label=_("Authentication code"),
        widget=forms.TextInput(attrs={'maxlength':'6', 'autocomplete': 'off'}),
        required=True)

    if user_auth_token.type == UserAuthToken.TYPE_HOTP:
        fields["token"].help_text = _(u"Enter the paper code number %(token_number)d from your printed two-factor code set here.") % dict(token_number=user_auth_token.counter+1)
        #fields["token"].help_text = _(u"Enter the paper code number from your printed two-factor code set here. Mark your used codes.")
    else:
        fields["token"].help_text = _(u"Enter the six-digit number from your mobile app here.")


class TwoFactorMixin(object):
    """ Mix-in form which adds mobile or paper based two-factor authentication token processing to any form.

    Do not use on the forms if the user does not have two-factor authentication enabled.

    Example::

        class DisableTwoFactorForm(forms.Form, TwoFactorMixin):
        " The user disable the use of two-factor authentication. This forms prompts user to enter the authentication code to disable two-factor. "

        def __init__(self, user, *args, **kwargs):
            forms.Form.__init__(self, *args, **kwargs)
            TwoFactorMixin.__init__(self, user)

        def save(self):
            UserAuthToken.objects.filter(user=self.user).delete()
            return self.user
    """

    def __init__(self, user):
        self.user = user

        try:
            self.user_auth_token = UserAuthToken.objects.get(user=self.user)
        except UserAuthToken.DoesNotExist:
            self.user_auth_token = None

        if self.user_auth_token:
            retrofit_token_field(self.fields, self.user_auth_token)

    def clean_token(self):
        """ Make sure the user entered the token"""

        assert self.user_auth_token, "User has two-factor authentication disabled. Should not end up here."

        token = self.cleaned_data.get('token')

        token = token.strip()
        for c in token:
            if not c.isdigit():
                raise forms.ValidationError(_(u"Token must contain only digits 0-9."))

        if len(token) != 6:
            raise forms.ValidationError(_(u"Token must be six digits long."))

        if not self.user_auth_token.check_auth_code(token):
            if self.user_auth_token.type == UserAuthToken.TYPE_HOTP:
                raise forms.ValidationError(_(u"This doesn't seem to match with the code on the paper. Please try again."))
            else:
                raise forms.ValidationError(_(u"The code does not match. Make sure your mobile phone has correct time. You can synchronize the time in Authenticator app settings."))
