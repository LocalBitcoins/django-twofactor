from django import forms
from django_twofactor.models import UserAuthToken
from django_twofactor import util


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

    def save(self):
        try:
            token = UserAuthToken.objects.get(user=self.user)
        except UserAuthToken.DoesNotExist:
            token = UserAuthToken(user=self.user)

        base36_with_checksum = self.cleaned_data["key"]
        seed = util.key_to_seed(base36_with_checksum)
        token.type = UserAuthToken.TYPE_HOTP
        token.reset_seed(seed)
        token.counter = 1
        token.save()
