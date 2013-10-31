from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate

from django_twofactor.models import UserAuthToken

ERROR_MESSAGE = _("Please enter the correct username, password and "
    "authentication code (if applicable). Note that all fields are "
    "case-sensitive.")


class TwoFactorAuthenticationForm(AuthenticationForm):
    """ Allow two-factor login, either with username or email """
    token = forms.CharField(label=_("Authentication Code"),
        help_text="If you have enabled two-factor authentication on your user account enter the six-digit number from your Google Authenticator mobile app here. Otherwise leave empty.",
        widget=forms.TextInput(attrs={'maxlength':'6', 'autocomplete': 'off'}),
        required=False
    )

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')
        token = self.cleaned_data.get('token')

        # Allow login with email
        try:
            u = User.objects.get(username=username)
        except User.DoesNotExist:
            try:
                u = User.objects.get(email=username)
                username = u.username
            except User.DoesNotExist:
                pass

        if username and password:
            self.user_cache = authenticate(username=username, password=password, token=token)
            if self.user_cache is None:
                raise forms.ValidationError(ERROR_MESSAGE)
            elif not self.user_cache.is_active:
                raise forms.ValidationError(_("This account is inactive."))
        self.check_for_test_cookie()
        return self.cleaned_data


class TwoFactorMixin(object):
    """ Mix-in form which adds mobile or paper based two-factor authentication token processing to any form.

    Do not use on the forms if the user does not two-factor authentication enabled.
    """

    token = forms.CharField(label=_("Authentication code"),
        widget=forms.TextInput(attrs={'maxlength':'6', 'autocomplete': 'off'}),
        required=False
    )

    def __init__(self, user):
        self.user = user

        try:
            self.user_auth_token = UserAuthToken.objects.get(user=self.user)
        except UserAuthToken.DoesNotExist:
            self.user_auth_token = None

        if self.user_auth_token:
            if self.user_token.type == UserAuthToken.TYPE_HOTP:
                self.fields["token"].help_text = _(u"Enter the paper code number %(token_number)d from your two-factor code ticket here.") % dict(token_number=self.user_token.counter)
            else:
                self.fields["token"].help_text = _(u"Enter the six-digit number from your mobile app here.")

    def clean_token(self):
        """ Make sure the user entered the token"""

        assert self.user_auth_token, "User has two-factor authentication disabled. Should not end up here."

        token = self.cleaned_data.get('token')
        if not self.user_auth_token.check_auth_code(token):
            if self.user_token.type == UserAuthToken.TYPE_HOTP:
                raise forms.ValidationError(_(u"This doesn't seem to match with the code on the paper. Please try again."))
            else:
                raise forms.ValidationError(_(u"The code does not match. Make sure your mobile phone has correct time. You can synchronize the time in Authenticator app settings."))



class TwoFactorAdminAuthenticationForm(TwoFactorAuthenticationForm):
    this_is_the_login_form = forms.BooleanField(widget=forms.HiddenInput,
        initial=1,  error_messages={'required': _("Please log in again, "
            "because your session has expired.")})
