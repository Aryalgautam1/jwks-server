# JWKS Server - Project 2

A Flask-based JWKS (JSON Web Key Set) server with SQLite database integration for CSCE 3550.

## Overview

This server issues JWTs (JSON Web Tokens) signed with RSA keys and provides public keys through a JWKS endpoint. Keys are stored in an SQLite database with automatic seeding on startup.

## Features

- **RSA Key Management**: Generates and stores 2048-bit RSA keys in SQLite
- **JWT Authentication**: Issues JWTs signed with RS256 algorithm
- **JWKS Endpoint**: Serves public keys in standard JWKS format
- **Database Storage**: Persistent key storage using SQLite
- **SQL Injection Safe**: All queries use parameterized statements
- **Automatic Seeding**: Seeds expired and valid keys on first run
- **Test Coverage**: 93% code coverage with comprehensive unit tests

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### Run Server

```bash
python -m app.server
```

Server starts on `http://localhost:8080`

### Run Tests

```bash
pytest -q --cov
```

## API Endpoints

### GET /.well-known/jwks.json
Returns public keys in JWKS format (non-expired keys only).

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "2",
      "n": "<base64url-encoded-modulus>",
      "e": "AQAB"
    }
  ]
}
```

### POST /auth
Issues a valid JWT signed with a non-expired key.

**Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIi..."
}
```

### POST /auth?expired=true
Issues an expired JWT for testing purposes.

**Error Responses:**
- `400`: No valid/expired key available

## Database Schema

```sql
CREATE TABLE keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

- `kid`: Auto-incrementing key identifier
- `key`: Private key in PKCS#1 PEM format
- `exp`: Unix timestamp for expiration

## Project Structure

```
jwks-server/
├── app/
│   ├── database.py       # Database connection and schema
│   ├── jwks_utils.py     # Key serialization and JWK conversion
│   ├── key_store.py      # SQL-safe key storage functions
│   └── server.py         # Flask application and endpoints
├── tests/
│   └── test_app.py       # Unit tests
├── conftest.py           # Pytest configuration
├── pytest.ini            # Test settings
├── requirements.txt      # Dependencies
└── README.md
```

## Dependencies

- Flask - Web framework
- PyJWT - JWT operations
- cryptography - RSA key generation
- pytest - Testing framework
- pytest-cov - Code coverage

## Testing

Run all tests:
```bash
pytest -v --cov
```

Test coverage: **93%**

## Security

- ✅ Parameterized SQL queries (SQL injection prevention)
- ✅ No string formatting in SQL statements
- ✅ Private keys never exposed in API responses
- ✅ Proper error handling with appropriate HTTP status codes

## Notes

- Keys are automatically seeded on first run (1 expired, 1 valid)
- Valid keys expire after 1 hour
- Database file: `totally_not_my_privateKeys.db`
- PKCS#1 (TraditionalOpenSSL) format for private keys

## License

Educational project for CSCE 3550 - Computer Systems Foundations

## Author

Gautam Aryal  
University of North Texas  
Fall 2025
