import time
import uuid
from dataclasses import dataclass
from typing import Dict, Tuple, List, Optional

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@dataclass
class KeyEntry:
    kid: str
    private_pem: bytes
    public_pem: bytes
    expiry: int  # unix timestamp (seconds)


class KeyStore:
    """
    Very simple in-memory keystore.
    - Generates one active key (future expiry) and one expired key (past expiry) at startup.
    - Provides helpers to fetch active/expired keys and payload expiries.
    """

    def __init__(self, active_lifetime_s: int = 600, expired_age_s: int = 3600) -> None:
        self._keys: Dict[str, KeyEntry] = {}
        now = int(time.time())

        # Generate active key (valid for active_lifetime_s from now)
        self.active_kid = self._generate_key(expiry=now + active_lifetime_s)

        # Generate expired key (expired expired_age_s seconds ago)
        self.expired_kid = self._generate_key(expiry=now - expired_age_s)

    def _generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    def _generate_key(self, expiry: int) -> str:
        private_pem, public_pem = self._generate_rsa_keypair()
        kid = str(uuid.uuid4())
        self._keys[kid] = KeyEntry(
            kid=kid, private_pem=private_pem, public_pem=public_pem, expiry=expiry
        )
        return kid

    def get_key(self, kid: str) -> Optional[KeyEntry]:
        return self._keys.get(kid)

    def get_active_keys(self) -> List[KeyEntry]:
        now = int(time.time())
        return [k for k in self._keys.values() if k.expiry > now]

    def get_active_key(self) -> KeyEntry:
        # Return the known active key by id (created at init)
        return self._keys[self.active_kid]

    def get_expired_key(self) -> KeyEntry:
        return self._keys[self.expired_kid]
