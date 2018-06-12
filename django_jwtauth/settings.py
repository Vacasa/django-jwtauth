"""
For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""
import os

SECRET_KEY = os.getenv('SECRET_KEY', '!INSECURE!')

AUTH_USER_MODEL = 'auth.User'

INSTALLED_APPS = [
    'django',
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django_jwtauth',
]
MIGRATION_MODULES = {
    'django_jwtauth': 'django_jwtauth.migrations'
}

PROJECT_PATH = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(PROJECT_PATH, 'django_jwtauth.sqlite'),
    }
}

# JWT Settings
DJANGO_JWTAUTH = {
    'JWT_ALGORITHM': 'RS256',
    'JWT_AUDIENCE': 'JWT_AUDIENCE',
    'JWT_ISSUER': 'JWT_ISSUER',
    'JWT_CACHE_ALIAS': 'default',
    'UNAUTHENTICATED_USER': 'auth.User',
}
