# Task 4 (Security / Auth): Request Account tests -> Screen 6
from config import ADMIN
from helpers import call, body

GOOD = {
    "fullName": "Test User",
    "email": "new.user@corp.com",
    "password": "Str0ng#Pass1",
    "requestedRole": "Analyst",
    "acceptedPolicy": True,
}


def send(**changes):
    data = dict(GOOD)
    data.update(changes)
    return call("POST", "/auth/request-account", json_body=data)


def test_valid_request_is_accepted():
    assert send().status_code == 202


def test_cannot_request_security_admin():
    # privilege escalation: this role is given by hand only
    assert send(requestedRole="Security Admin").status_code in (400, 403, 422)


def test_security_admin_is_not_in_requestable_roles():
    r = call("GET", "/roles/requestable")
    assert "Security Admin" not in r.json()


def test_weak_password_is_rejected():
    assert send(password="123").status_code == 422


def test_policy_must_be_accepted():
    assert send(acceptedPolicy=False).status_code == 422


def test_existing_email_looks_the_same_as_a_new_one():
    a = send(email=ADMIN[0])
    b = send(email="brand.new@corp.com")
    assert a.status_code == b.status_code
    assert body(a) == body(b)
