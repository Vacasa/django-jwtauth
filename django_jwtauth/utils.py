import jwt
import requests

from os import path, mkdir

from time import time
from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from django.conf import settings
from django.core.cache import caches
from django.contrib.auth import get_user_model

from django_jwtauth.models import RemoteUser

cache = caches[settings.DJANGO_JWTAUTH['JWT_CACHE_ALIAS']]

_KEYS_DIR = path.join(path.dirname(path.realpath(__file__)), 'keys')
_PRIVATE_KEY_FILENAME = path.join(_KEYS_DIR, 'RS256.key')
_PUBLIC_KEY_FILENAME = path.join(_KEYS_DIR, 'RS256.key.pub')


def setup_keys():
    # If we don't have a key pair, we generate one. This should only happen once
    if not path.isdir(_KEYS_DIR):
        mkdir(_KEYS_DIR)
    if not path.isfile(_PRIVATE_KEY_FILENAME):
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        with open(_PRIVATE_KEY_FILENAME, 'w+') as private_key:
            private_key.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ).decode()
            )
        with open(_PUBLIC_KEY_FILENAME, 'w+') as public_key:
            public_key.write(
                key.public_key().public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH
                ).decode()
            )
    with open(_PRIVATE_KEY_FILENAME, 'r') as f:
        private_key = str(f.read())
    return private_key


def get_private_key():
    return setup_keys()


def get_public_key():
    if 'JWT_PUBLIC_KEY' in settings.DJANGO_JWTAUTH and settings.DJANGO_JWTAUTH['JWT_PUBLIC_KEY']:
        return settings.DJANGO_JWTAUTH['JWT_PUBLIC_KEY']
    if not path.isfile(_PUBLIC_KEY_FILENAME):
        setup_keys()
    with open(_PUBLIC_KEY_FILENAME, 'r') as f:
        return str(f.read())


def generate_jwt_for_user(local_user):
    '''
    Django-JWTAuth correlates users from two domains: the local domain (in the app where we're using Django-JWTAuth)
    and the Token generator's domain (which is NOT Django-JWTAuth except when testing)
    :param local_user: type(get_user_model())
    :return: jwt token (as string)
    '''

    claims = {
        'iss': settings.DJANGO_JWTAUTH['JWT_ISSUER'],
        'aud': settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],
        'exp': int(time()) + 3600,  # 1 hour
        'iat': int(time())  # issued at
    }

    remote_user, created = RemoteUser.objects.get_or_create(
        iss=claims['iss'],
        local_user=local_user,
        defaults={'sub': str(local_user.id)}
    )

    claims['sub'] = remote_user.sub
    token = jwt.encode(
        payload=claims,
        key=get_private_key(),
        algorithm=settings.DJANGO_JWTAUTH['JWT_ALGORITHM']
    )

    return token.decode('utf-8')


def verify_token(token):
    '''
    Verify that:
        We
    :param token: jwt token (as bytes)
    :return: type(get_user_model())
    '''
    # use sha256 to reduce key size
    token_sha = sha256(token.encode('utf-8')).hexdigest()

    # Check to see if this token is in the cache
    # we set TTL when we insert, so its existence means it hasn't expired
    # If it exists in the cache, we don't need to verify it
    verify = not cache.get(token_sha)

    # If token DNE in cache, we need to verify it first
    # In the case that the token isn't cached, we need to decode and verify the signature
    # In the case that it is in the cache, we need to decode to get the 'sub' and 'iss' claims to look up the user
    claims = jwt.decode(
        token=token,
        verify=verify,
        audience=settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],
        issuer=settings.DJANGO_JWTAUTH['JWT_ISSUER'],
        key=get_public_key(),
        algorithms=[settings.DJANGO_JWTAUTH['JWT_ALGORITHM']]
    )

    # We are identifying the user either by the azp or the sub claim
    user_id = None
    if 'sub' in claims:
        user_id = claims['sub']
    elif 'azp' in claims:
        user_id = claims['azp']
    else:
        return False

    # If it's a valid token from an issuer we trust, we need to see if there's a user record associated
    try:
        # Now we check to see whether we have a user in our local db
        # that corresponds to the subject and issuer ('sub', 'azp', 'iss') claims in our token
        remote_user = RemoteUser.objects.get(sub=user_id, iss=claims['iss'])

    except RemoteUser.DoesNotExist:
        # if the user isn't found, we'll hit here
        # Not having a remote user user means that we don't have a local user,
        # so we'll create done of each
        local_user = get_user_model().objects.create()
        remote_user = RemoteUser.objects.create(
            sub=user_id,
            iss=claims['iss'],
            local_user=local_user
        )

    # If we get here, the user exists in the db, so we add their token to the cache
    if verify:
        cache.set(token_sha, 1, max(0, int(claims['exp'] - time())))

    return remote_user.local_user


def swap_auth_code_for_token(code):
    r = requests.post(
        settings.OAUTH['OAUTH_TOKEN_ENDPOINT'],
        json={
            "grant_type": "authorization_code",
            "client_id": settings.OAUTH['OAUTH_CLIENT_ID'],
            "client_secret": settings.OAUTH['OAUTH_CLIENT_SECRET'],
            "code": code,
            "redirect_uri": settings.OAUTH['OAUTH_CALLBACK_URL']
        }
    )

    r.raise_for_status()
    return r.json()
