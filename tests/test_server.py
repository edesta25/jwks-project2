import os
import tempfile
import time

import jwt
import pytest

import server


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()

    original_db = server.DB_FILE
    server.DB_FILE = db_path

    server.init_db()
    server.seed_keys_if_needed()

    server.app.config["TESTING"] = True
    with server.app.test_client() as test_client:
        yield test_client

    os.close(db_fd)
    os.unlink(db_path)
    server.DB_FILE = original_db


def test_db_file_created(client):
    assert os.path.exists(server.DB_FILE)


def test_jwks_returns_keys(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1

    jwk = data["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert "kid" in jwk
    assert "n" in jwk
    assert "e" in jwk


def test_auth_returns_valid_jwt(client):
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.get_data(as_text=True)
    assert token.count(".") == 2

    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert "kid" in header
    assert payload["sub"] == "userABC"
    assert payload["username"] == "userABC"
    assert payload["exp"] > int(time.time())


def test_auth_expired_returns_expired_jwt(client):
    response = client.post("/auth?expired=1")
    assert response.status_code == 200

    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert "kid" in header
    assert payload["sub"] == "userABC"
    assert payload["exp"] <= int(time.time())


def test_jwks_only_returns_valid_keys(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = response.get_json()
    returned_kids = {item["kid"] for item in data["keys"]}

    valid_rows = server.fetch_valid_keys()
    valid_kids = {str(row["kid"]) for row in valid_rows}

    assert returned_kids == valid_kids


def test_fetch_signing_key_valid(client):
    row = server.fetch_signing_key(use_expired=False)
    assert row is not None
    assert row["exp"] > int(time.time())


def test_fetch_signing_key_expired(client):
    row = server.fetch_signing_key(use_expired=True)
    assert row is not None
    assert row["exp"] <= int(time.time())
