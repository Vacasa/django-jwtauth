from django.db import models
from django.contrib.auth import get_user_model


class RemoteUser(models.Model):
    """
    User model with issuer and subscriber claims from the token provider and a foreign key to our local user model (cached model).

    Extends django.db.models.Model
    """

    iss = models.CharField(max_length=128, null=False)
    claim_identifier = models.CharField(max_length=128, null=False)
    local_user = models.ForeignKey(get_user_model(), null=True, on_delete=models.CASCADE)
