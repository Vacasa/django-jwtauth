import jwt
import requests

from time import time
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import rsa

from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import PermissionDenied

from .utils import get_public_key


def verify_jwt_from_header(request, *args, **kwargs):
    if 'HTTP_AUTHORIZATION' not in request.META:
        raise PermissionDenied

    bearer = request.META['HTTP_AUTHORIZATION'].split(' ')[1]

    try:
        claims = jwt.decode(
            bearer,
            key=get_public_key(),
            algorithms=[settings.DJANGO_JWTAUTH['JWT_ALGORITHM']],
            *args,
            **kwargs,
        )

        return claims
    except (
        jwt.PyJWTError
    ) as e:
        raise PermissionDenied(str(e))
