"""Tests for the JWKS server."""
import json
import time

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

import app as server


@pytest.fixture
def client():
    """Fresh keys and a Flask test client for every test."""
    server.init_keys()
    return server.app.test_client()


def expired_kid():
    """Return the kid of the expired key."""
    return next(k["kid"] for k in server.KEYS if k["expiry"] <= time.time())


def test_generate_key():
    key = server.generate_key(3600)
    assert key["kid"]
    assert key["expiry"] > time.time()


def test_generate_expired_key():
    key = server.generate_key(-3600)
    assert key["expiry"] < time.time()


def test_int_to_b64url():
    # 65537 is the usual RSA exponent and encodes to AQAB
    assert server.int_to_b64url(65537) == "AQAB"


def test_jwks_returns_only_unexpired_key(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] != expired_kid()


def test_jwks_key_fields(client):
    key = client.get("/.well-known/jwks.json").get_json()["keys"][0]
    for field in ("kty", "use", "alg", "kid", "n", "e"):
        assert field in key
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"


def test_jwks_wrong_method(client):
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_auth_returns_valid_jwt(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    jwk = client.get("/.well-known/jwks.json").get_json()["keys"][0]
    assert jwt.get_unverified_header(token)["kid"] == jwk["kid"]
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    payload = jwt.decode(token, public_key, algorithms=["RS256"])
    assert payload["exp"] > time.time()


def test_auth_expired_uses_expired_key(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    assert jwt.get_unverified_header(token)["kid"] == expired_kid()
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["exp"] < time.time()


def test_auth_wrong_method(client):
    assert client.get("/auth").status_code == 405
