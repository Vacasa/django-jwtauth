import uuid
from io import StringIO
from os import path
from shutil import rmtree

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from django.contrib.auth import get_user_model

from django_jwtauth.utils import setup_keys, verify_token, get_private_key

OUT = StringIO()


class GenerateTokenTestCase(TestCase):

    def setUp(self):
        self.test_user = get_user_model().objects.create(
            first_name="test_first_name",
            last_name="test_last_name",
            email="test_first_name.test_last_name@test_domain.com",
            is_active=True,
            is_superuser=False
        )

    def test_command_raises_without_debug(self):
        with self.assertRaises(CommandError):
            call_command('generate_token', stdout=OUT)

    def test_command_raises_error_missing_args(self):
        with self.settings(DEBUG=True):
            with self.assertRaises(CommandError):
                call_command('generate_token', stdout=OUT)

    def test_command(self):
        with self.settings(DEBUG=True):
            call_command('generate_token', user=str(self.test_user.id), stdout=OUT)

    def test_command_keys_only_generate_once(self):
        with self.settings(DEBUG=True):
            token = call_command('generate_token', user=str(self.test_user.id), stdout=OUT)
        private_key = setup_keys()
        self.assertEqual(private_key, get_private_key())

    def test_command_uses_test_user(self):
        with self.settings(DEBUG=True):
            token = call_command('generate_token', user=str(self.test_user.id), stdout=OUT)
        user = verify_token(token)
        self.assertEqual(user.id, self.test_user.id)

    def test_command_email(self):
        with self.settings(DEBUG=True):
            token = call_command('generate_token', email=self.test_user.email, stdout=OUT)
        user = verify_token(token)
        self.assertEqual(user.id, self.test_user.id)

    def test_command_raises_dne_error(self):
        with self.settings(DEBUG=True):
            with self.assertRaises(CommandError):
                call_command('generate_token', user=uuid.uuid4(), stdout=OUT)

    def test_command_raises_invalid_uuid_error(self):
        with self.settings(DEBUG=True):
            with self.assertRaises(CommandError):
                call_command('generate_token', user='invalid_uuid', stdout=OUT)
