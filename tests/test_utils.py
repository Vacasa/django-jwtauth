import jwt

from os import path
from shutil import rmtree
from time import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings, tag

from django_jwtauth import utils


class UtilsTestCase(TestCase):

    def setUp(self):
        self.claims = {
            'iss': settings.DJANGO_JWTAUTH['JWT_ISSUER'],  # issuer
            'sub': 'test_user',  # subject (user)
            'aud': settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],  # audience
            'exp': int(time()) + 10,  # expiration time
            'iat': int(time())  # issued at
        }

    def test_setup_keys_creates_keys(self):
        rmtree(utils._KEYS_DIR)
        self.assertFalse(path.isfile(utils._PRIVATE_KEY_FILENAME))
        self.assertFalse(path.isfile(utils._PUBLIC_KEY_FILENAME))
        utils.setup_keys()
        self.assertTrue(path.isfile(utils._PRIVATE_KEY_FILENAME))
        self.assertTrue(path.isfile(utils._PUBLIC_KEY_FILENAME))

    @override_settings(DJANGO_JWTAUTH={'JWT_PUBLIC_KEY': 'key'})
    def test_get_public_key_uses_key_from_settings_when_set(self):
        self.assertEqual(utils.get_public_key(), 'key')

    @override_settings(DJANGO_JWTAUTH={'JWT_PUBLIC_KEY': ''})
    def test_get_public_key_does_not_use_key_from_settings_when_set_to_empty(self):
        self.assertNotEqual(utils.get_public_key(), '')

    @override_settings(DJANGO_JWTAUTH={})
    def test_get_public_key_does_not_use_key_from_settings_when_JWT_PUBLIC_KEY_not_set(self):
        with open(utils._PUBLIC_KEY_FILENAME, 'r') as f:
            key = str(f.read())
        self.assertEqual(utils.get_public_key(), key)

    def test_private_key_does_not_change_after_setup_keys(self):
        private_key = utils.get_private_key()
        utils.setup_keys()
        self.assertEqual(utils.get_private_key(), private_key)

    def test_verify_token_passes_with_sub(self):
        user = get_user_model()()
        user.save()
        token = utils.generate_jwt_for_user(user)
        local_user = utils.verify_token(token)
        self.assertIsInstance(local_user, get_user_model())

    def test_verify_token_passes_with_azp(self):
        user = get_user_model()()
        user.save()
        token = utils.generate_jwt_for_user(user, use_azp=True)
        local_user = utils.verify_token(token)
        self.assertIsInstance(local_user, get_user_model())

    def test_generate_token_returns_sub_claim(self):
        user = get_user_model()()
        user.save()
        token = utils.generate_jwt_for_user(user, use_azp=False)
        claims = jwt.decode(
            token=token,
            verify=False,
            audience=settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],
            issuer=settings.DJANGO_JWTAUTH['JWT_ISSUER'],
            key=utils.get_public_key(),
            algorithms=[settings.DJANGO_JWTAUTH['JWT_ALGORITHM']]
        )
        self.assertIn('sub', claims)

    def test_generate_token_returns_azp_claim(self):
        user = get_user_model()()
        user.save()
        token = utils.generate_jwt_for_user(user, use_azp=True)
        claims = jwt.decode(
            token=token,
            verify=False,
            audience=settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],
            issuer=settings.DJANGO_JWTAUTH['JWT_ISSUER'],
            key=utils.get_public_key(),
            algorithms=[settings.DJANGO_JWTAUTH['JWT_ALGORITHM']]
        )
        self.assertIn('azp', claims)
