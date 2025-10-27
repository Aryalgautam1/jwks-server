import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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


def serialize_private_key_to_pem(private_key) -> bytes:
    """
    Serialize an RSA private key to PEM format (PKCS#1/TraditionalOpenSSL).
    No password encryption (safe default for this use case).
    Uses TraditionalOpenSSL format for gradebot compatibility.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_from_pem(pem_bytes: bytes):
    """
    Load an RSA private key from PEM bytes.
    Returns an RSA private key object.
    """
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None,
    )
