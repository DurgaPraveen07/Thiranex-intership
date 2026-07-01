from __future__ import annotations

import re
from typing import Dict, List, Set

MIN_PASSWORD_LENGTH = 12
SPECIAL_CHAR_PATTERN = r'[!@#$%^&*(),.?":{}|<>]'

COMMON_PASSWORDS: Set[str] = {
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
}


def is_common_password(password: str) -> bool:
    """Return True when a password matches a known weak password.

    The lookup is normalized to lower case and trimmed to catch simple
    variants such as leading or trailing whitespace.
    """

    normalized_password = password.strip().lower()
    return normalized_password in COMMON_PASSWORDS


def check_password_strength(password: str) -> Dict[str, object]:
    """Evaluate a password and return a structured assessment.

    The score is bounded to 5 points and reflects the following criteria:
    length, uppercase presence, lowercase presence, digit presence, and
    special-character presence.

    The common-password check is treated as a hard failure and is not counted
    in the score so the numeric score remains a simple 0-5 measure of
    composition quality.
    """

    feedback: List[str] = []
    score = 0

    if password is None:
        password = ""

    if password.strip() == "":
        feedback.append("Password cannot be empty or whitespace only")

    if len(password) >= MIN_PASSWORD_LENGTH:
        score += 1
    else:
        feedback.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing an uppercase letter")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing a lowercase letter")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Missing a digit")

    if re.search(SPECIAL_CHAR_PATTERN, password):
        score += 1
    else:
        feedback.append("Missing a special character")

    if is_common_password(password):
        feedback.append("Password is too common")

    is_strong = score == 5 and not is_common_password(password) and password.strip() != ""

    return {
        "is_strong": is_strong,
        "score": score,
        "feedback": feedback,
    }


# Future extension:
# def check_password_against_pwned_api(password: str) -> bool:
#     """Check a password against an external breach database.
#
#     A production implementation could query the Have I Been Pwned API using
#     k-anonymity, sending only the first few characters of the password hash
#     prefix and comparing the returned suffixes locally.
#     """
#     raise NotImplementedError


def _prompt_for_password() -> str:
    """Prompt the user for a password, handling blank input cleanly."""

    try:
        return input("Enter a password to check (blank to quit): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


if __name__ == "__main__":
    print("Password Strength Checker")
    print("Type a password and press Enter. Submit a blank line to exit.\n")

    while True:
        candidate = _prompt_for_password()
        if candidate == "":
            break

        result = check_password_strength(candidate)
        print(f"Strong: {result['is_strong']}")
        print(f"Score: {result['score']}/5")

        if result["feedback"]:
            print("Feedback:")
            for message in result["feedback"]:
                print(f"- {message}")
        else:
            print("Feedback: None")

        print()
