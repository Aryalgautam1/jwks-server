JWKS Server (Python/Flask)
Tiny server for CSCE 3550 Project 1. It issues JWTs, serves a JWKS of only active keys, and can purposely mint an expired token for testing. 

--------------------------------------------------------------------------------------------------------------------------------------------
What it does
Generates two RSA keys at startup: active (future expiry) + expired (past).
JWKS: GET /jwks and GET /.well-known/jwks.json (active keys only).
Auth:
POST /auth → valid JWT (RS256, header includes kid)
POST /auth?expired=true → expired JWT (signed by expired key)
--------------------------------------------------------------------------------------------------------------------------------------------
Run it
python -m venv .venv
# Windows
.venv\Scripts\activate.bat
pip install -r requirements.txt
python -m app.server
# http://127.0.0.1:8080
--------------------------------------------------------------------------------------------------------------------------------------------
Quick checks (PowerShell)
irm http://localhost:8080/jwks | ConvertTo-Json -Depth 5
$good = irm -Method POST http://localhost:8080/auth; $good.token
$bad  = irm -Method POST "http://localhost:8080/auth?expired=true"; $bad.token
--------------------------------------------------------------------------------------------------------------------------------------------
Endpoints
JWKS
GET /jwks
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "9fc65c9b-3724-419d-838a-6b5748929f74",
      "n": "<base64url modulus>",
      "e": "AQAB"
    }
  ]
}

Auth
POST /auth → returns a valid token (signed by the active key)

POST /auth?expired=true → returns an expired token (signed by the expired key)
--------------------------------------------------------------------------------------------------------------------------------------------

GET /.well-known/jwks.json ← used by some tools/gradebot
Tests & gradebot
pytest
--------------------------------------------------------------------------------------------------------------------------------------------
