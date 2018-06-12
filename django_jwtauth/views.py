from urllib.parse import quote_plus
import json

import jwt

from django.views import View
from django.views.generic import TemplateView
from django.core.exceptions import ValidationError, PermissionDenied
from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib.auth import get_user_model
from django.http import JsonResponse

from django.middleware import csrf

from .utils import (
    verify_token,
    generate_jwt_for_user,
    swap_auth_code_for_token
)


class LoginView(View):
    """
    When anonymous users request a protected page they will be redirected here.
    We construct an authorization URL and return a redirect to it
    """

    def get(self, request, *args, **kwargs):
        """
        We need a random string to use as the `state` param.
        Django's CSRF token does the trick so we'll generate it
        and save it to the session.

        :param Django.http.HttpRequest request: Request that led them here.
        :return: The login view where the user can log in via redirect.
        :rtype: response.HttpResponsePermanentRedirect
        """
        request.session['state'] = csrf.get_token(request)

        if 'next' in request.GET:
            request.session['next'] = request.GET['next']

        url = settings.OAUTH['OAUTH_AUTHORIZE_ENDPOINT'] + '?'
        url += "audience={}&".format(settings.OAUTH['OAUTH_AUDIENCE'])
        url += "response_type=code&"
        url += "scope=profile email openid&"
        url += "client_id={}&".format(settings.OAUTH['OAUTH_CLIENT_ID'])
        url += "state={}&".format(request.session.get('state'))
        url += "redirect_uri={}".format(quote_plus(settings.OAUTH['OAUTH_CALLBACK_URL']))
        return redirect(url)


class LogoutView(View):
    """
    Logs the user out and redirects them to the page they were viewing.
    """
    template_name = "oauth/logout_confirm.html"

    def get(self, request, *args, **kwargs):
        """
        Logout view that will log the user out and return the page specified in request.

        :param Django.http.HttpRequest request: request submitted by the user to log out.
        :return: redirect to the next page or to the logout page.
        :rtype: response.HttpResponsePermanentRedirect
        """
        if not request.user or request.user.is_authenticated is False:
            return redirect(request.GET.get('next', settings.LOGOUT_REDIRECT_URL or '/'))

        return render(
            request,
            self.template_name
        )

    def post(self, request, *args, **kwargs):
        """
        Logs the user out and redirects them back to where they came from.

        :param Django.http.HttpRequest request: request submitted by the user to log out
        :return: redirect to the next page or to the logout page.
        :rtype: response.HttpResponsePermanentRedirect
        """

        if request.user.is_authenticated is True:
            request.session.flush()

        return redirect(request.GET.get('next', settings.LOGOUT_REDIRECT_URL or '/'))


class CallbackView(View):
    """
    This is the view for the callback URL that receives an authorization code
    and uses it to request an access token from the Oauth2 Provider
    """

    def get(self, request, *args, **kwargs):
        """
        Takes a request with a code and swaps that code for an auth token from the auth
        provider specified in settings, and then handles the request for that
        authenticated user.

        :param request: The request with a request.GET['code'] with an auth code for user
        :return: redirect to the page requested.
        :rtype: response.HttpResponsePermanentRedirect
        """

        if 'code' not in request.GET:
            raise ValidationError("Missing or invalid `code` parameter.")

        if 'state' not in request.GET:
            raise ValidationError("Missing or invalid `state` parameter.")

        session_state = request.session.get('state')
        request_state = request.GET['state']

        if session_state != request_state:
            raise PermissionDenied('Invalid state.')

        # This is where we need to make a request to the Oauth server
        # to exchange the authorization code for an access token
        response = swap_auth_code_for_token(request.GET['code'])

        user = verify_token(response['access_token'])

        if 'id_token' in response:
            claims = jwt.decode(
                token=response['id_token'],
                verify=False,
                audience=settings.DJANGO_JWTAUTH['JWT_AUDIENCE'],
                issuer=settings.DJANGO_JWTAUTH['JWT_ISSUER']
            )
            user.email = claims['email']
            user.save()

        request.session['SESSION_USER_ID'] = user.id

        return redirect(request.session.get('next', "/"))


class AuthorizeView(TemplateView):
    """
    This is a dummy authorization view that can be used for local logins. This
    should NEVER be used in production.
    """
    template_name = "oauth/login_form.html"

    def post(self, request, *args, **kwargs):
        """
        Authorize the user via a post request submitted through the dummy view
        with a valid email address in request.POST['email']

        :param request: Request submitted by the user with email for authorization.
        :return: Redirect to the OAUTH_CALLBACK_URL with code & state.
        :rtype: response.HttpResponsePermanentRedirect
        """

        try:
            user = get_user_model().objects.get(email=request.POST['email'])
        except Exception as e:
            return render(
                request,
                self.template_name,
                {
                    'error': str(e),
                    'email': request.POST['email']
                }, status=400
            )

        url = settings.OAUTH['OAUTH_CALLBACK_URL'] + '?'
        # For simplicity we're using the user's ID as the authorization code
        url += "code={}&".format(user.id)
        url += "state={}".format(request.GET['state'])
        return redirect(url)


class TokenView(View):
    """
    This is a dummy token view for local development. This should NEVER be used
    in production.
    """

    def post(self, request, *args, **kwargs):
        """
        Take a user_id via request.POST['code'] and generate a jwt token for testing.

        :param request: Request with code/user_id to generate a token for.
        :return: Json response with the token, type, and seconds until expiration.
        :rtype: JsonResponse
        """

        data = json.loads(request.body.decode('utf-8'))

        # Assume the authorization code is a user id
        user_id = data['code']
        user = get_user_model().objects.get(pk=user_id)
        token = generate_jwt_for_user(user)
        return JsonResponse({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600
        })
