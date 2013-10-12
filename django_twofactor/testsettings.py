DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
    }
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django_twofactor",
]

AUTHENTICATION_BACKENDS = (
    'django_twofactor.auth_backends.TwoFactorAuthBackend',
)

SECRET_KEY = "sekrit"


TWOFACTOR_TOTP_OPTIONS = {
        "period": 30,
        "default_token_type": "dec6",
        # Specify drifts for the unlucky scenario where the period ends after
        # the correct seed is calculated but before authenticate is called
        "forward_drift": 2,
        "backward_drift": 2,
}

TWOFACTOR_ENCRYPTION_KEY = ""
