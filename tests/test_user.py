from django.conf import settings
from django.test import TestCase, override_settings, RequestFactory
# import test user model
from .models import User

class UserTestCase(TestCase):

    def test_create_user(self):
        user, created = User.objects.get_or_create(
            first_name="test_first_name",
            last_name="test_last_name",
            username="test_user_one",
            email="test_first_name.test_last_name@test_domain.com",
            is_active=True,
            is_superuser=False
        )

        self.assertTrue(isinstance(user, User))
        
        user_two, created_two = User.objects.get_or_create(
            first_name="test_first_name_two",
            last_name="test_last_name_two",
            username="test_user_two",
            email="two_test_first_name.test_last_name@test_domain.com",
            is_active=True,
            is_superuser=False
        )

        self.assertTrue(isinstance(user_two, User))