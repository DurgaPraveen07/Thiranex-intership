import pyotp


def get_or_create_secret(profile):
    """Return a stable TOTP secret for the profile."""
    if not profile.secret_key:
        profile.secret_key = pyotp.random_base32()
        profile.save(update_fields=["secret_key", "updated_at"])
    return profile.secret_key


def build_provisioning_uri(profile, issuer_name="Secure Login System"):
    secret = get_or_create_secret(profile)
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=profile.user.email or profile.user.username, issuer_name=issuer_name)


def verify_token(profile, token):
    if not profile.secret_key:
        return False
    totp = pyotp.TOTP(profile.secret_key)
    return totp.verify(token, valid_window=1)
