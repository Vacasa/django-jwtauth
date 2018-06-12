# JSON Web Token (JWT) Authentication with Django

[![Maintainability](https://api.codeclimate.com/v1/badges/93c2ec4567dd362cd9eb/maintainability)](https://codeclimate.com/github/Vacasa/django-jwtauth/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/93c2ec4567dd362cd9eb/test_coverage)](https://codeclimate.com/github/Vacasa/django-jwtauth/test_coverage)

## Overview

The `django_jwtauth` library allows the use of JSON Web Tokens from third-party identity providers in Django applications. `django-jwtauth` is NOT intended to
turn your Django project into a token issuer. It is only intended to enable your Django project as a consumer of third-party JWT.

The library relies on Django for caching, authentication, testing, and web stuff (content-types and templates). The `cryptography` and `requests` libraries
are only used to enable local development by generating tokens (and verifying them).


## Requirements

- Django
- cryptography
- PyJWT
- requests

## Installation

Install using `pip`:

`pip install django_jwtauth`

Add `django_jwtauth` to your `INSTALLED_APPS` setting:

```python
INSTALLED_APPS = (
    ...
    'django_jwtauth',
)
```

## DJANGO_JWTAUTH settings

Add `DJANGO_JWTAUTH` settings to `settings.py`:

```python
DJANGO_JWTAUTH = {
    'JWT_PUBLIC_KEY': '< your public key >' # A public key from your third-party JWT issuer
    'JWT_ALGORITHM': '< RS256 | HS256 >', # This should match the algorithm used by the JWT issuer
    'JWT_AUDIENCE': '< your JWT audience >', # Consult with your issuer to determine how they set this claim
    'JWT_ISSUER': '< your JWT issuer >', # # Consult with your issuer to determine how they set this claim
    'JWT_CACHE_ALIAS': '< your cache alias >', # django-jwtauth uses django caching by default. Use this setting to point to the appropriate cache alias
    'UNAUTHENTICATED_USER': '< your user >', # Used in middleware when the request doesn't have a local user that we can find.
}
```

## OAuth2 Provider Settings

Add `OAUTH` settings to `settings.py`:

```python
OAUTH = {
    'OAUTH_AUTHORIZE_ENDPOINT': '< your authorize endpoint >',
    'OAUTH_TOKEN_ENDPOINT': '< your token endpoint >',
    'OAUTH_CLIENT_ID': '< your client ID >',
    'OAUTH_CLIENT_SECRET': '< your client secret >',
    'OAUTH_AUDIENCE': DJANGO_JWTAUTH['JWT_AUDIENCE'],
    'OAUTH_CALLBACK_URL': BASE_URL + '/oauth/callback'
}
```

Add `LOGIN_URL` and `LOGOUT_URL` settings to `settings.py`:

```python
LOGIN_URL = BASE_URL + '/oauth/login'
LOGOUT_URL = BASE_URL + '/oauth/logout'
```

## Development Notes

If you use `django-jwtauth` without a public key in `settings.DJANGO_JWTAUTH['JWT_PUBLIC_KEY']`, a public/private key pair will be created in the /keys directory
wherever you have `django-jwtauth` installed. `django-jwtauth` will use these unless and until `settings.DJANGO_JWTAUTH['JWT_PUBLIC_KEY']` is set. This is
done so that in development, we can operate as a JWT provider ourselves, using the `utils.generate_jwt_for_user()` function to generate a token (using our
local private key) which will then be valid (validated using our local public key). This is included only as a stop-gap to enable local development without
requiring a third-party JWT issuer.
