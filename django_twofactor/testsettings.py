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
        "forward_drift": 0,
        "backward_drift": 0,
        "default_token_type": "dec6",
}

TWOFACTOR_ENCRYPTION_KEY = ""
