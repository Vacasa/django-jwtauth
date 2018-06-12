import jwt

from hashlib import sha256
from datetime import datetime
from copy import deepcopy
from time import time

from django.test import TestCase, override_settings
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.contrib.auth import get_user_model
from django.test.client import RequestFactory

from django_jwtauth.authentication import JWTAuthentication
from django_jwtauth.models import RemoteUser
from django_jwtauth.utils import PRIVATE_KEY


class JWTAuthenticationTestCase(TestCase):
    seconds = datetime.now().timestamp()

    def setUp(self):
        # create a user and save it so that we can test some caching stuff
        self.factory = RequestFactory()

        self.claims = {
            'iss': settings.DJANGO_JWTAUTH['JWT_ISSUER'],  # issuer
            'sub': 'test_user',  # subject (user)
            'aud': settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],  # audience
            'exp': int(time()) + 10,  # expiration time
            'iat': int(time())  # issued at
        }

    def jwt_encode_as_bearer(self, payload):
        return "Bearer {}".format(jwt.encode(
            payload=payload,
            key=PRIVATE_KEY,
            algorithm=settings.DJANGO_JWTAUTH['JWT_ALGORITHM']
        ).decode('utf-8'))

    @override_settings(DJANGO_JWTAUTH={'UNAUTHENTICATED_USER': None})
    def test_authentication_passes_without_auth_header(self):
        request = self.factory.get('/test')
        jwtauth = JWTAuthentication()
        self.assertEqual(None, jwtauth.authenticate(request))

    def test_authentication_raises_with_invalid_auth_header_not_enough_segments(self):
        request = self.factory.get('/test', HTTP_AUTHORIZATION="Bearer <token>")
        jwtauth = JWTAuthentication()
        with self.assertRaises(jwt.exceptions.DecodeError):
            jwtauth.authenticate(request)

    def test_authentication_passes_with_valid_auth_header_and_token(self):
        request = self.factory.get('/test', HTTP_AUTHORIZATION="Bearer <token>")
        jwtauth = JWTAuthentication()
        with self.assertRaises(jwt.exceptions.DecodeError):
            jwtauth.authenticate(request)

    def test_authentication_raises_authentication_failed_with_no_iss_claim(self):
        claims = deepcopy(self.claims)
        del(claims['iss'])
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=claims))
        jwtauth = JWTAuthentication()
        with self.assertRaises(PermissionDenied):
            jwtauth.authenticate(request)

    def test_authentication_raises_authentication_failed_with_no_aud_claim(self):
        claims = deepcopy(self.claims)
        del(claims['aud'])
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=claims))
        jwtauth = JWTAuthentication()
        with self.assertRaises(PermissionDenied):
            jwtauth.authenticate(request)

    def test_authentication_passes_with_required_claims(self):
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        user_auth = jwtauth.authenticate(request)
        self.assertTrue(user_auth[0].is_authenticated)

    def test_authentication_raises_authentication_failed_with_bad_aud_claim(self):
        self.claims['aud'] = 'brentmydland'
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        with self.assertRaises(PermissionDenied):
            jwtauth.authenticate(request)

    def test_authentication_raises_authentication_failed_with_expired_exp_claim(self):
        self.claims['exp'] = datetime.now().timestamp() - 10
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        with self.assertRaises(PermissionDenied):
            jwtauth.authenticate(request)

    def test_authentication_uses_cache_with_existing_token(self):
        # get something into the cache
        self.claims['exp'] = datetime.now().timestamp() - 10
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        with self.assertRaises(PermissionDenied):
            jwtauth.authenticate(request)

    def test_authentication_finds_existing_token_in_cache(self):
        # insert a token in the cache
        token = self.jwt_encode_as_bearer(payload=self.claims).split(" ")[1].encode('utf-8')
        jwt_sha = sha256(token).hexdigest()
        cache.set(jwt_sha, 1)
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        auth_tuple = jwtauth.authenticate(request)
        self.assertIsInstance(auth_tuple[0], get_user_model())
        self.assertIsNotNone(auth_tuple[1])
        cache.delete(jwt_sha)

    def test_authentication_creates_vjwt_user_when_user_dne(self):
        # first make sure the db is clean
        with self.assertRaises(RemoteUser.DoesNotExist):
            RemoteUser.objects.get(sub=self.claims['sub'], iss=self.claims['iss'])
        # request should populate the db
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        jwtauth = JWTAuthentication()
        self.assertIsInstance(jwtauth.authenticate(request)[0], get_user_model())
        new_vjwt_user = RemoteUser.objects.get(sub=self.claims['sub'], iss=self.claims['iss'])
        self.assertIsInstance(new_vjwt_user, RemoteUser)

    def test_authentication_creates_auth_user_when_user_dne(self):
        # first make sure the db is clean
        # with self.assertRaises(RemoteUser.DoesNotExist):
        self.assertEqual(list(get_user_model().objects.all()), [])

        # request should populate the db
        token = self.jwt_encode_as_bearer(payload=self.claims)
        JWTAuthentication().authenticate(self.factory.get('/test', HTTP_AUTHORIZATION=token))
        self.assertNotEqual(list(get_user_model().objects.all()), [])

    def test_authentication_returns_user_model(self):
        # request should populate the db
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        self.assertFalse(hasattr(request, 'user'))
        jwtauth = JWTAuthentication()
        auth_tuple = jwtauth.authenticate(request)
        self.assertIsInstance(auth_tuple[0], get_user_model())

    def test_authentication_returns_active_user(self):
        # request should populate the db
        request = self.factory.get('/test', HTTP_AUTHORIZATION=self.jwt_encode_as_bearer(payload=self.claims))
        self.assertFalse(hasattr(request, 'user'))
        jwtauth = JWTAuthentication()
        auth_tuple = jwtauth.authenticate(request)
        self.assertTrue(auth_tuple[0].is_authenticated)
