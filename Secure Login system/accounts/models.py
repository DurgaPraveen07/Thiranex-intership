from django.conf import settings
from django.db import models


class TwoFactorProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor_profile")
    secret_key = models.CharField(max_length=64, blank=True)
    is_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"TwoFactorProfile({self.user.username})"
