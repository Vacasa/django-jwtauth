import sys
import json
from importlib import reload
from urllib.parse import urlparse
from unittest import mock

import jwt

from django.test import TestCase, override_settings, RequestFactory
from django.urls import reverse, clear_url_caches
from django.core.exceptions import ValidationError, PermissionDenied
from django.conf import settings
from django.contrib.auth.models import User

from django_jwtauth.utils import generate_jwt_for_user
from django_jwtauth.views import CallbackView, LogoutView

overrides = {
    "MIDDLEWARE": [
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django_jwtauth.middleware.AuthenticationMiddleware'
    ],
    "OAUTH": {
        'OAUTH_AUTHORIZE_ENDPOINT': 'https://oauthserver.com/authorize',
        'OAUTH_TOKEN_ENDPOINT': 'https://oauthserver.com/authorize',
        'OAUTH_CLIENT_ID': '12345',
        'OAUTH_CLIENT_SECRET': '54321',
        'OAUTH_AUDIENCE': 'test.api.com',
        'OAUTH_CALLBACK_URL': 'https://127.0.0.1/callback'
    }
}


def get_test_user():
    user, created = User.objects.get_or_create(
        first_name="test_first_name",
        last_name="test_last_name",
        email="test_first_name.test_last_name@test_domain.com",
        is_active=True,
        is_superuser=False
    )
    return user


def mocked_requests_post(*args, **kwargs):
    
    class MockResponse(object):

        def raise_for_status(self):
            return True

        def json(self):
            user = get_test_user()
            access_token = generate_jwt_for_user(user)
            id_token = jwt.encode(
                {
                    'email': user.email
                },
                'secret', algorithm='HS256'
            ).decode('utf-8')
            return {
                "access_token": access_token,
                "id_token": id_token,
                "token_type": "Bearer"
            }

    return MockResponse()


def mocked_requests_post_no_id_token(*args, **kwargs):
    
    class MockResponseNoToken(object):

        def raise_for_status(self):
            return True

        def json(self):
            user = get_test_user()
            access_token = generate_jwt_for_user(user)
            return {
                "access_token": access_token,
                "token_type": "Bearer"
            }

    return MockResponseNoToken()


@override_settings(**overrides)
class LoginViewTestCase(TestCase):
    
    def test_get(self):
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 302)
        o = urlparse(response['Location'])
        self.assertEqual(o.scheme, 'https')
        self.assertEqual(o.netloc, 'oauthserver.com')
        self.assertEqual(o.path, '/authorize')

    def test_get_with_next(self):
        response = self.client.get(reverse("login") + '?next=/users')
        self.assertEqual(response.status_code, 302)


@override_settings(**overrides)
class LogoutViewTestCase(TestCase):

    def setUp(self):
        reload(sys.modules['django_jwtauth.urls'])
        reload(sys.modules[settings.ROOT_URLCONF])
        clear_url_caches()

    def test_get(self):
        request = RequestFactory().get(reverse('logout') + '?next=/users')
        request.user = get_test_user()
        request.session = {}
        response = LogoutView.as_view()(request)
        self.assertEqual(response.status_code, 200)

    def test_get_no_user(self):
        response = self.client.get(reverse('logout') + '?next=/users')
        self.assertEqual(response.status_code, 302)

    def test_post(self):
        request = RequestFactory().post(reverse('logout') + '?next=/users')
        request.user = get_test_user()

        request.session = self.client.session
        request.session['SESSION_USER_ID'] = '123456'
        # request.session.save()

        response = LogoutView.as_view()(request)

        self.assertEqual(response.status_code, 302)

        o = urlparse(response['Location'])
        self.assertEqual(o.path, '/users')

    def test_post_not_authenticated(self):
        request = RequestFactory().post(reverse('logout') + '?next=/users')
        request.user = get_test_user()
        request.user.authenticated = False

        request.session = self.client.session
        request.session['SESSION_USER_ID'] = '123456'
        # request.session.save()

        response = LogoutView.as_view()(request)

        self.assertEqual(response.status_code, 302)


@override_settings(**overrides)
class CallbackViewTestCase(TestCase):

    @mock.patch('requests.post', side_effect=mocked_requests_post)
    def test_get(self, mock_post):
        request = RequestFactory().get(reverse("callback") + '?code=12345&state=12345')
        request.session = {'state': '12345'}
        response = CallbackView.as_view()(request)
        self.assertEqual(response.status_code, 302)

    @mock.patch('requests.post', side_effect=mocked_requests_post_no_id_token)
    def test_get_missing_token(self, mock_post):
        request = RequestFactory().get(reverse("callback") + '?code=12345&state=12345')
        request.session = {'state': '12345'}
        response = CallbackView.as_view()(request)
        self.assertEqual(response.status_code, 302)

    def test_get_missing_code(self):
        request = RequestFactory().get(reverse("callback") + '?state=12345')
        request.session = {'state': '12345'}
        with self.assertRaises(ValidationError):
            CallbackView.as_view()(request)

    def test_get_missing_state(self):
        request = RequestFactory().get(reverse("callback") + '?code=12345')
        request.session = {'state': '12345'}
        with self.assertRaises(ValidationError):
            CallbackView.as_view()(request)

    def test_get_invalid_state(self):
        request = RequestFactory().get(reverse("callback") + '?code=12345&state=foobar')
        request.session = {'state': '12345'}
        with self.assertRaises(PermissionDenied):
            CallbackView.as_view()(request)

    


@override_settings(**overrides, DEBUG=True)
class AuthorizeViewTestCase(TestCase):

    def setUp(self):
        reload(sys.modules['django_jwtauth.urls'])
        reload(sys.modules[settings.ROOT_URLCONF])
        clear_url_caches()

    def test_get(self):
        response = self.client.get(reverse("authorize"))
        self.assertEqual(response.status_code, 200)

    def test_post(self):
        user = get_test_user()
        response = self.client.post(
            reverse("authorize") + '?state=12345',
            {'email': user.email}
        )
        self.assertEqual(response.status_code, 302)

    def test_post_invalid_user(self):
        response = self.client.post(
            reverse("authorize") + '?state=12345',
            {'email': 'foo@bar.com'}
        )
        self.assertEqual(response.status_code, 400)


@override_settings(**overrides, DEBUG=True)
class TokenViewTestCase(TestCase):

    def setUp(self):
        reload(sys.modules['django_jwtauth.urls'])
        reload(sys.modules[settings.ROOT_URLCONF])
        clear_url_caches()

    def test_post(self):
        user = get_test_user()
        data = {
            'code': str(user.id)
        }
        response = self.client.post(
            reverse("token"),
            json.dumps(data),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
