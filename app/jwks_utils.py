import base64
from cryptography.hazmat.primitives.asymmetric import rsa


def _int_to_base64url(n: int) -> str:
    """Convert integer to base64url without padding, per JWK spec."""
    if n == 0:
        return "AA"  # shouldn't occur for RSA n/e, but keeps function total
    byte_length = (n.bit_length() + 7) // 8
    data = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_key_to_jwk(public_key, kid: str) -> dict:
    """
    Convert an RSA public key to a JWK dict for JWKS endpoint (RFC 7517).
    Includes kty, use, alg, kid, n, e.
    """
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }
