from io import StringIO

from django.test import TestCase, override_settings, tag
from django.contrib.auth import get_user_model
from django.test.client import RequestFactory

from django_jwtauth.middleware import AuthenticationMiddleware, get_unauthenticated_user

OUT = StringIO()


class MockAnonymousUser(object):
    pass


class GetUnauthenticatedUserTestCase(TestCase):

    @override_settings(DJANGO_JWTAUTH={'UNAUTHENTICATED_USER': None})
    def test_get_unauthenticated_user_none(self):
        self.assertEqual(get_unauthenticated_user(), None)

    @override_settings(DJANGO_JWTAUTH={'UNAUTHENTICATED_USER': 'tests.test_middleware.MockAnonymousUser'})
    def test_get_unauthenticated_user_string(self):
        self.assertEqual(type(get_unauthenticated_user()), MockAnonymousUser)

    @override_settings(DJANGO_JWTAUTH={'UNAUTHENTICATED_USER': MockAnonymousUser})
    def test_get_unauthenticated_user_class(self):
        self.assertEqual(type(get_unauthenticated_user()), MockAnonymousUser)


@override_settings(MIDDLEWARE=[
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django_jwtauth.middleware.AuthenticationMiddleware'
])
class AuthenticationMiddlewareTestCase(TestCase):

    def setUp(self):
        self.test_user = get_user_model().objects.create(
            first_name="test_first_name",
            last_name="test_last_name",
            email="test_first_name.test_last_name@test_domain.com",
            is_active=True,
            is_superuser=False
        )

    def test_user_attached_to_request(self):
        factory = RequestFactory()
        request = factory.get('/tests')
        request.session = {}
        request.session['SESSION_USER_ID'] = self.test_user.id
        middleware = AuthenticationMiddleware(lambda x: "Response!")
        middleware(request)
        self.assertEqual(request.user.id, self.test_user.id)

    @override_settings(DJANGO_JWTAUTH={'UNAUTHENTICATED_USER': None})
    def test_user_does_not_exist(self):
        factory = RequestFactory()
        request = factory.get('/tests')
        request.session = {}
        request.session['SESSION_USER_ID'] = self.test_user.id
        self.test_user.delete()
        middleware = AuthenticationMiddleware(lambda x: "Response!")
        middleware(request)
        self.assertEqual(request.user, None)
