import uuid
from django.db import models


class User(models.Model):
    """
    Model for representing a user.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=128, null=True)
    last_name = models.CharField(max_length=128, null=True)
    email = models.EmailField(null=True, unique=True)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)
    last_seen = models.DateField(null=True)

    REQUIRED_FIELDS = ()
    USERNAME_FIELD = 'id'

    is_anonymous = False
    authenticated = True

    class Meta:
        ordering = ['created_at']

    @property
    def is_authenticated(self):
        """
        This is a way to tell if the user has been
        authenticated in templates.
        Snarfed from django.contrib.auth.base_user
        """
        return self.authenticated
