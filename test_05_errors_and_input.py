# Task 5 (Security / Auth): bad input and error messages -> all screens
import requests
from config import BASE
from helpers import call

ENDPOINTS = ["/auth/login", "/auth/forgot-password", "/auth/request-account", "/auth/verify-otp", "/auth/reset-password"]
ODD_VALUES = ["' OR '1'='1", "a" * 5000, "<script>alert(1)</script>", "../../etc/passwd", None, 123]


def test_odd_input_never_gives_a_server_error():
    for path in ENDPOINTS:
        for odd in ODD_VALUES:
            data = {"email": odd, "password": odd, "code": odd, "newPassword": odd, "resetToken": odd}
            r = call("POST", path, json_body=data)
            assert r.status_code < 500, (path, odd)


def test_errors_do_not_show_stack_traces():
    for path in ENDPOINTS:
        r = call("POST", path, json_body={})
        for word in ["StackTrace", "System.", "Traceback"]:
            assert word not in r.text, (path, word)


def test_login_with_a_body_that_is_not_json():
    r = requests.post(BASE + "/auth/login", data="not json", timeout=15)
    assert r.status_code < 500
