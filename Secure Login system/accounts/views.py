from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse

from .forms import LoginForm, OTPForm, RegistrationForm
from .models import TwoFactorProfile
from .services.two_factor import build_provisioning_uri, get_or_create_secret, verify_token


def home_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    return redirect("login")


def register_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    form = RegistrationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Registration successful. Please log in.")
        return redirect("login")

    return render(request, "accounts/register.html", {"form": form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    form = LoginForm(request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.get_user()
        profile, _ = TwoFactorProfile.objects.get_or_create(user=user)
        if profile.is_enabled:
            request.session["pre_2fa_user_id"] = user.id
            request.session.set_expiry(300)
            return redirect("two_factor_verify")

        login(request, user)
        messages.success(request, "Logged in securely.")
        return redirect("dashboard")

    return render(request, "accounts/login.html", {"form": form})


@login_required
def dashboard_view(request):
    profile, _ = TwoFactorProfile.objects.get_or_create(user=request.user)
    return render(
        request,
        "accounts/dashboard.html",
        {
            "profile": profile,
        },
    )


@login_required
def two_factor_setup_view(request):
    profile, _ = TwoFactorProfile.objects.get_or_create(user=request.user)
    secret = get_or_create_secret(profile)
    provisioning_uri = build_provisioning_uri(profile)
    form = OTPForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        token = form.cleaned_data["token"]
        if verify_token(profile, token):
            profile.is_enabled = True
            profile.save(update_fields=["is_enabled", "updated_at"])
            messages.success(request, "Two-factor authentication is now enabled.")
            return redirect("dashboard")
        form.add_error("token", "The verification code is invalid or expired.")

    return render(
        request,
        "accounts/two_factor_setup.html",
        {
            "form": form,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "profile": profile,
        },
    )


def two_factor_verify_view(request):
    user_id = request.session.get("pre_2fa_user_id")
    if not user_id:
        return redirect("login")

    form = OTPForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            profile = TwoFactorProfile.objects.select_related("user").get(user_id=user_id)
        except TwoFactorProfile.DoesNotExist:
            request.session.pop("pre_2fa_user_id", None)
            return redirect("login")

        if verify_token(profile, form.cleaned_data["token"]):
            login(request, profile.user)
            request.session.pop("pre_2fa_user_id", None)
            request.session.set_expiry(None)
            messages.success(request, "Two-factor verification complete.")
            return redirect("dashboard")
        form.add_error("token", "Invalid verification code.")

    return render(request, "accounts/two_factor_verify.html", {"form": form})


def logout_view(request):
    logout(request)
    request.session.flush()
    messages.info(request, "You have been logged out.")
    return redirect("login")
