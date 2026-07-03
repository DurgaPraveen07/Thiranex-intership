from django.urls import path

from . import views

urlpatterns = [
    path("", views.home_view, name="home"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("two-factor/setup/", views.two_factor_setup_view, name="two_factor_setup"),
    path("two-factor/verify/", views.two_factor_verify_view, name="two_factor_verify"),
]
