import time
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization

from app.key_store import KeyStore
from app.jwks_utils import public_key_to_jwk


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False  # keep JWKS order readable

    # Key store: one active key (future expiry) and one expired key (past expiry)
    keystore = KeyStore(active_lifetime_s=600, expired_age_s=3600)  # 10 min active, 1 hr ago expired
    app.keystore = keystore  # attach for tests

    # ---- Helper to build the JWKS payload (only non-expired keys) ----
    def _jwks_payload() -> dict:
        keys = []
        for entry in keystore.get_active_keys():
            public_key = serialization.load_pem_public_key(entry.public_pem)
            keys.append(public_key_to_jwk(public_key, entry.kid))
        return {"keys": keys}

    # Original JWKS route (keep)
    @app.get("/jwks")
    def jwks():
        """Return JWKS with only NON-EXPIRED keys (per assignment)."""
        return jsonify(_jwks_payload()), 200

    # Well-known JWKS endpoint gradebot expects
    @app.get("/.well-known/jwks.json")
    def well_known_jwks():
        """Standard JWKS discovery path."""
        return jsonify(_jwks_payload()), 200

    @app.post("/auth")
    def auth():
        """
        POST /auth
        - No body required (per blackbox test).
        - If ?expired=true, sign a JWT with the expired key and an already-expired 'exp'.
        - Otherwise, sign with the active key and a valid 'exp' (not beyond key expiry).
        Always include 'kid' in the JWT header.
        """
        use_expired = request.args.get("expired", "").lower() in ("1", "true", "yes")
        if use_expired:
            entry = keystore.get_expired_key()
            exp = entry.expiry  # already in the past
        else:
            entry = keystore.get_active_key()
            now = int(time.time())
            exp = min(entry.expiry, now + 300)  # <=5 minutes, and not past key expiry

        headers = {"kid": entry.kid}
        payload = {
            "sub": "fake-user",  # mocking auth per assignment
            "iat": int(time.time()),
            "exp": exp,
        }
        token = jwt.encode(payload, entry.private_pem, algorithm="RS256", headers=headers)
        return jsonify({"token": token}), 200

    @app.get("/")
    def health():
        return jsonify({"status": "ok"}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    # Serve HTTP on port 8080 (per assignment)
    app.run(host="0.0.0.0", port=8080)
