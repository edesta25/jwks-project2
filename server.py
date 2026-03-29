import base64
import sqlite3
import time

import jwt
from flask import Flask, Response, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


DB_FILE = "totally_not_my_privateKeys.db"
app = Flask(__name__)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def pem_to_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key")
    return key


def seed_keys_if_needed() -> None:
    now = int(time.time())
    conn = get_db_connection()
    try:
        expired_count = conn.execute(
            "SELECT COUNT(*) AS count FROM keys WHERE exp <= ?",
            (now,),
        ).fetchone()["count"]

        valid_count = conn.execute(
            "SELECT COUNT(*) AS count FROM keys WHERE exp > ?",
            (now,),
        ).fetchone()["count"]

        if expired_count == 0:
            expired_key = generate_private_key()
            expired_pem = private_key_to_pem(expired_key)
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (expired_pem, now - 3600),
            )

        if valid_count == 0:
            valid_key = generate_private_key()
            valid_pem = private_key_to_pem(valid_key)
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (valid_pem, now + 3600),
            )

        conn.commit()
    finally:
        conn.close()


def fetch_signing_key(use_expired: bool):
    now = int(time.time())
    conn = get_db_connection()
    try:
        if use_expired:
            row = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
        return row
    finally:
        conn.close()


def fetch_valid_keys():
    now = int(time.time())
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            ORDER BY kid ASC
            """,
            (now,),
        ).fetchall()
        return rows
    finally:
        conn.close()


def b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def private_key_row_to_jwk(row) -> dict:
    private_key = pem_to_private_key(row["key"])
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": str(row["kid"]),
        "n": b64url_uint(numbers.n),
        "e": b64url_uint(numbers.e),
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    rows = fetch_valid_keys()
    keys = [private_key_row_to_jwk(row) for row in rows]
    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    use_expired = "expired" in request.args
    row = fetch_signing_key(use_expired)

    if row is None:
        return jsonify({"error": "No suitable key found"}), 500

    private_key = pem_to_private_key(row["key"])
    now = int(time.time())

    payload = {
        "sub": "userABC",
        "username": "userABC",
        "iat": now,
        "exp": row["exp"],
    }

    headers = {"kid": str(row["kid"])}

    token = jwt.encode(payload, private_key, algorithm="RS256", 
headers=headers)
    return Response(token, mimetype="text/plain")


def startup():
    init_db()
    seed_keys_if_needed()


startup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
