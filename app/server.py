import time
import logging
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from app.database import init_db, get_db_connection
from app.key_store import save_key, get_key, get_valid_keys
from app.jwks_utils import (
    public_key_to_jwk,
    serialize_private_key_to_pem,
    load_private_key_from_pem,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def seed_keys_if_empty():
    """
    Seed two keys if the database is empty:
    - expired: exp = now - 5 seconds
    - valid: exp = now + 3600 seconds
    Logs their DB kid values.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM keys")
    count = cursor.fetchone()["count"]
    conn.close()
    
    if count == 0:
        logger.info("Database is empty. Seeding with 2 RSA keys...")
        now = int(time.time())
        
        # Generate expired key
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = serialize_private_key_to_pem(expired_key)
        expired_kid = save_key(expired_pem, now - 5)
        logger.info(f"Seeded expired key with kid={expired_kid}, exp={now - 5}")
        
        # Generate valid key
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_pem = serialize_private_key_to_pem(valid_key)
        valid_kid = save_key(valid_pem, now + 3600)
        logger.info(f"Seeded valid key with kid={valid_kid}, exp={now + 3600}")
    else:
        logger.info(f"Database already contains {count} key(s). Skipping seed.")


def create_app() -> Flask:
    # Initialize database on startup
    init_db()
    
    # Seed two keys if DB is empty
    seed_keys_if_empty()
    
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False  # keep JWKS order readable

    # ---- Helper to build the JWKS payload (only non-expired keys) ----
    def _jwks_payload() -> dict:
        keys = []
        for kid, pem_bytes, exp_ts in get_valid_keys():
            private_key = load_private_key_from_pem(pem_bytes)
            public_key = private_key.public_key()
            # Convert kid to string for JWK format
            keys.append(public_key_to_jwk(public_key, str(kid)))
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
        - Reads 'expired' query param (truthy if present)
        - Fetches key via get_key(expired=...)
        - Signs JWT (RS256) with 'kid' header and exp claim aligned to stored exp
        - Returns {"token": "<jwt>"}
        - Returns 400 if no key matches
        """
        # Check if expired param is truthy
        expired_param = request.args.get("expired", "")
        use_expired = expired_param.lower() in ("1", "true", "yes")
        
        # Fetch key from database
        key_data = get_key(expired=use_expired)
        
        if key_data is None:
            error_msg = f"No {'expired' if use_expired else 'valid'} key available"
            logger.error(error_msg)
            return jsonify({"error": error_msg}), 400
        
        kid, pem_bytes, exp_ts = key_data
        
        # Load private key
        private_key = load_private_key_from_pem(pem_bytes)
        
        # Create JWT with kid in header
        headers = {"kid": str(kid)}
        payload = {
            "sub": "fake-user",  # mocking auth per assignment
            "iat": int(time.time()),
            "exp": exp_ts,  # Use the stored exp from DB
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        return jsonify({"token": token}), 200

    @app.get("/")
    def health():
        return jsonify({"status": "ok"}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    # Serve HTTP on port 8080 (per assignment)
    app.run(host="0.0.0.0", port=8080)
