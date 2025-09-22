import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app.server import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _get_public_key_pem(app, kid):
    entry = app.keystore.get_key(kid)
    return entry.public_pem


def test_jwks_contains_only_active_keys(client):
    resp = client.get("/jwks")
    assert resp.status_code == 200
    data = resp.get_json()
    kids = [k["kid"] for k in data["keys"]]
    app = client.application
    assert app.keystore.active_kid in kids
    assert app.keystore.expired_kid not in kids  # expired should not be served


def test_auth_returns_valid_jwt_with_kid_header(client):
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # Inspect header to ensure kid present and matches active
    header = jwt.get_unverified_header(token)
    app = client.application
    assert header["kid"] == app.keystore.active_kid

    # Verify signature and expiration using public key
    pub_pem = _get_public_key_pem(app, header["kid"])
    public_key = serialization.load_pem_public_key(pub_pem)
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"


def test_auth_expired_query_issues_expired_jwt_and_uses_expired_kid(client):
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    header = jwt.get_unverified_header(token)

    app = client.application
    assert header["kid"] == app.keystore.expired_kid

    pub_pem = _get_public_key_pem(app, header["kid"])
    public_key = serialization.load_pem_public_key(pub_pem)

    # Signature should be valid, but token should be expired
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])

    # If we disable exp verification, decoding should work (proves it's signed by the expired key)
    decoded = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": False})
    assert decoded["sub"] == "fake-user"
