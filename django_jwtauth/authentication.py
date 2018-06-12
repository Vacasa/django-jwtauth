from jwt import exceptions

from django.core.exceptions import PermissionDenied

from .utils import verify_token


class JWTAuthentication(object):

    def authenticate(self, request):
        '''
        Authenticate the token by checking its authenticity with our utility class.

        :param request: Django.http.HttpRequest
        :return: user, token
        :rtype: django.contrib.auth.get_user_model(), string
        :throws PermissionDenied: If the token is expired or has invalid claims.
        '''

        if 'HTTP_AUTHORIZATION' not in request.META:
            return None

        # Get the token out of Auth header
        token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]

        try:
            user = verify_token(token)
        except (
            exceptions.ExpiredSignatureError,
            exceptions.InvalidAudienceError,
            exceptions.InvalidIssuerError,
            exceptions.MissingRequiredClaimError,
        ) as e:
            # for claims issues, we re-raise the exception to allow a helpful user feedback message to be created
            raise PermissionDenied(str(e))

        return user, token
    
    def authenticate_header(self, request):
        return "Bearer"
