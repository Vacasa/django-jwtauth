import os

SECRET_KEY = os.getenv('SECRET_KEY', '!INSECURE!')
ROOT_URLCONF = 'django_jwtauth.urls'
AUTH_USER_MODEL = 'tests.User'

INSTALLED_APPS = [
    'django',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django_jwtauth',
    'tests',
]
DJANGO_JWTAUTH = {
    'JWT_ALGORITHM': 'RS256',
    'JWT_AUDIENCE': 'jwt_test_audience',
    'JWT_ISSUER': 'jwt_test_issuer',
    'JWT_CACHE_ALIAS': 'default',
}
PROJECT_PATH = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(PROJECT_PATH, 'django_jwtauth.sqlite'),
    }
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['django_jwtauth/templates'],
    }
]
# CACHES
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "KEY_PREFIX": "jwt"
    }
}

# SESSIONS
SESSION_CACHE_ALIAS = "default"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
