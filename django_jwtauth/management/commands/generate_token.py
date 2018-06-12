from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.contrib.auth import get_user_model

from django_jwtauth.utils import generate_jwt_for_user


class Command(BaseCommand):
    '''
    Using Django's BaseCommand, this gives us a CLI option to generate a jwt token
    for local testing. The token will be signed by a private key from the keys/ directory
    (located wherever this package is installed). A key pair will be generated the first
    time this library is used, if it han't been created already.
    '''

    help = 'Generates a JWT token local testing.'

    def add_arguments(self, parser):
        # Named (optional) arguments
        parser.add_argument(
            '--user',
            dest='user',
            help='User ID of the user to be making requests.',
        )
        parser.add_argument(
            '--email',
            dest='email',
            help='Email address of the user to be making requests.',
        )

    def get_user(self, options):
        '''
        When passing in a user by email address or uuid, we look up the user
        so that the token we ultimately return will be associated with an actual (local) user
        :param options:
        :return:
        '''
        user_model = get_user_model()
        try:
            if options['user']:
                return user_model.objects.get(id=options['user'])
            elif options['email']:
                return user_model.objects.get(email=options['email'])
            else:
                raise CommandError("--user or --email are required.")
        except get_user_model().DoesNotExist:
            raise CommandError("No user found matching id provided. ")
        except ValidationError:
            raise CommandError("Invalid user id provided. ")

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError("Tokens can only be generated when DEBUG = True.")
        local_user = self.get_user(options)
        return generate_jwt_for_user(local_user)
