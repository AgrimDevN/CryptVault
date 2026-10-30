"""Web-layer tests: auth flow, CSRF, headers, auto-lock."""
import re
import time

import pytest

import app as webapp
from conftest import FAST, PW
from cryptvault.vault import VaultService


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "service", VaultService(str(tmp_path / "w.db"), str(tmp_path / "c.json"), FAST))
    webapp.UNLOCKED.clear()
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()


def csrf(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


def login(c):
    c.post("/register", data={"username": "alice", "password": PW, "confirm": PW, "csrf": csrf(c, "/register")})
    return c.post("/login", data={"username": "alice", "password": PW, "csrf": csrf(c, "/login")})


def test_full_flow(client):
    assert login(client).status_code == 302
    tok = csrf(client, "/entry/new")
    client.post("/entry/new", data={"title": "GitHub", "username": "a", "password": "x", "csrf": tok})
    page = client.get("/vault").get_data(as_text=True)
    assert "GitHub" in page and "Verified" in page


def test_post_without_csrf_rejected(client):
    assert client.post("/login", data={"username": "a", "password": "b"}).status_code == 400
    assert client.post("/login", data={"username": "a", "password": "b", "csrf": "é"}).status_code == 400


def test_weak_master_password_rejected(client):
    tok = csrf(client, "/register")
    r = client.post("/register", data={"username": "z", "password": "password", "confirm": "password", "csrf": tok})
    assert b"does not meet the policy" in r.data


def test_security_headers(client):
    h = client.get("/login").headers
    assert h["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"


def test_auto_lock(client):
    login(client)
    for e in webapp.UNLOCKED.values():
        e["last_seen"] = time.time() - 10_000
    assert client.get("/vault").status_code == 302 and not webapp.UNLOCKED
