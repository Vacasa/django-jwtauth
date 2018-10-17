from shutil import rmtree
from os import path
from time import time
from copy import deepcopy
from django.conf import settings
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

    def test_verify_user_client_sub(self):
        self.assertEquals(self.claims['sub'], utils.verify_user_client(self.claims))

    def test_verify_user_client_azp(self):
        claims = deepcopy(self.claims)
        del(claims['sub'])
        claims['azp'] = 'c1l2i3e4n5t6i7d8' 

        self.assertEquals(claims['azp'], utils.verify_user_client(claims))
