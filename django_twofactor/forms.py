from django import forms
from django_twofactor.models import UserAuthToken


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
        self.token.regenerate_seed()
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
