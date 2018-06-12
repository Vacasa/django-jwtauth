from pydoc import locate
from django.conf import settings
from django.contrib.auth import get_user_model


def get_unauthenticated_user():

    if (
        not hasattr(settings, 'DJANGO_JWTAUTH') or
        'UNAUTHENTICATED_USER' not in settings.DJANGO_JWTAUTH or
        settings.DJANGO_JWTAUTH['UNAUTHENTICATED_USER'] is None
    ):
        return None

    setting = settings.DJANGO_JWTAUTH['UNAUTHENTICATED_USER']

    if (isinstance(setting, str)):
        return locate(setting)()

    return setting()


class AuthenticationMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        assert hasattr(request, 'session'), (
            "The django_jwtauth authentication middleware requires session middleware "
            "to be installed. Edit your MIDDLEWARE%s setting to insert "
            "'django.contrib.sessions.middleware.SessionMiddleware' before "
            "'django_jwtauth.middleware.AuthenticationMiddleware'."
        ) % ("_CLASSES" if settings.MIDDLEWARE is None else "")
        user_id = request.session.get('SESSION_USER_ID', None)
        user_model = get_user_model()

        request.user = get_unauthenticated_user()
        if user_id:
            try:
                request.user = user_model.objects.get(pk=user_id)
            except user_model.DoesNotExist:
                pass

        response = self.get_response(request)
        return response
