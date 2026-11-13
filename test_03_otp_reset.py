# Task 3 (Security / Auth): Forgot Password, OTP and Reset tests -> Screens 7, 8, 9
import os
import pytest
from config import ADMIN
from helpers import call, body

GHOST = "nobody@trust.local"


def forgot(email):
    return call("POST", "/auth/forgot-password", json_body={"email": email})


def verify(email, code):
    return call("POST", "/auth/verify-otp", json_body={"email": email, "code": code})


def test_forgot_password_gives_the_same_answer_for_any_email():
    a = forgot(ADMIN[0])
    b = forgot(GHOST)
    assert a.status_code == b.status_code == 202
    assert body(a).keys() == body(b).keys()


def test_wrong_otp_is_rejected_and_shows_attempts_left():
    forgot(ADMIN[0])
    r = verify(ADMIN[0], "000000")
    assert r.status_code == 400
    assert body(r).get("code") == "OTP_INVALID"
    assert "attemptsLeft" in body(r)


def test_otp_cannot_be_brute_forced():
    forgot(ADMIN[0])
    last = None
    for i in range(10):
        last = verify(ADMIN[0], str(100000 + i))
    assert last.status_code in (410, 429)


def test_resend_too_fast_is_limited():
    forgot(ADMIN[0])
    r = call("POST", "/auth/resend-otp", json_body={"email": ADMIN[0]})
    assert r.status_code == 429


def test_fake_reset_token_is_rejected():
    r = call("POST", "/auth/reset-password", json_body={"resetToken": "fake-token", "newPassword": "Str0ng#Pass1"})
    assert r.status_code in (400, 401, 410)


@pytest.mark.skipif(not os.getenv("RESET_TOKEN"), reason="set RESET_TOKEN (get it by doing the flow by hand)")
def test_weak_password_is_rejected():
    r = call("POST", "/auth/reset-password", json_body={"resetToken": os.getenv("RESET_TOKEN"), "newPassword": "123"})
    assert r.status_code == 422
