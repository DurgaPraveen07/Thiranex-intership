# Secure Login System

Thiranex Task 4 implementation: a secure login web application built with Django.

## Security features

- User registration and login using Django's authentication framework.
- Password hashing with Argon2 as the preferred hasher, with bcrypt available as a fallback.
- Input validation through Django forms to sanitize and normalize user data.
- SQL injection protection through Django ORM usage instead of raw SQL.
- Secure session handling with logout that invalidates the active session.
- Optional TOTP-based two-factor authentication using `pyotp`.

## Project structure

- `secure_login/`: Django project settings and routes.
- `accounts/`: Authentication app, forms, views, and 2FA helpers.
- `templates/`: HTML templates for login, registration, dashboard, and 2FA.

## Local setup

```bash
cd "Secure Login system"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## Notes

- `Argon2` is recommended for password hashing because it is intentionally expensive to brute-force.
- If you deploy this project, set `DEBUG = False` and keep `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True`.
- The 2FA workflow is modular and can be extended to show QR codes if needed.
