"""Simple JWKS server: serves public keys and issues signed JWTs."""
import base64
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)

# Holds all generated keys (each is a dict with kid, private key, expiry)
KEYS = []


def generate_key(expires_in):
    """Make an RSA key pair with a kid and an expiry timestamp."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    return {
        "kid": str(uuid.uuid4()),
        "private_key": private_key,
        "expiry": int(time.time()) + expires_in,
    }


def int_to_b64url(number):
    """Turn an integer into base64url text with no padding."""
    length = (number.bit_length() + 7) // 8
    raw = number.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def init_keys():
    """Create one valid key (1 hour) and one already-expired key."""
    KEYS.clear()
    KEYS.append(generate_key(3600))
    KEYS.append(generate_key(-3600))


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return only the public keys that have not expired."""
    now = time.time()
    keys = []
    for key in KEYS:
        if key["expiry"] > now:
            numbers = key["private_key"].public_key().public_numbers()
            keys.append({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key["kid"],
                "n": int_to_b64url(numbers.n),
                "e": int_to_b64url(numbers.e),
            })
    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    """Return a signed JWT. Use the expired key if ?expired is present."""
    now = time.time()
    if "expired" in request.args:
        key = next(k for k in KEYS if k["expiry"] <= now)
    else:
        key = next(k for k in KEYS if k["expiry"] > now)

    pem = key["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = {
        "sub": "fake-user",
        "iat": int(now),
        "exp": key["expiry"],
    }
    token = jwt.encode(
        payload, pem, algorithm="RS256", headers={"kid": key["kid"]}
    )
    return token, 200, {"Content-Type": "text/plain"}


init_keys()

if __name__ == "__main__":
    app.run(port=8080)
