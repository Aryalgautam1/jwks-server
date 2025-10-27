import time
from typing import Tuple, List, Optional

from app.database import get_db_connection


def save_key(pem_bytes: bytes, exp_ts: int) -> int:
    """
    Save a private key PEM to the database with expiry timestamp.
    Uses parameterized query for SQL injection safety.
    Returns the DB row kid (auto-generated).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (pem_bytes, exp_ts)
    )
    kid = cursor.lastrowid
    conn.commit()
    conn.close()
    return kid


def get_key(expired: bool) -> Optional[Tuple[int, bytes, int]]:
    """
    Get one key from the database.
    - If expired=True: choose one key with exp <= now
    - If expired=False: choose one key with exp > now
    
    Returns (kid:int, pem_bytes:bytes, exp_ts:int) or None if no matching key.
    Uses parameterized query for SQL injection safety.
    """
    now = int(time.time())
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if expired:
        # Get an expired key (exp <= now)
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
            (now,)
        )
    else:
        # Get a valid key (exp > now)
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
            (now,)
        )
    
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return None
    
    return (row["kid"], row["key"], row["exp"])


def get_valid_keys() -> List[Tuple[int, bytes, int]]:
    """
    Get all valid (non-expired) keys from the database.
    Returns list of (kid:int, pem_bytes:bytes, exp_ts:int).
    Uses parameterized query for SQL injection safety.
    """
    now = int(time.time())
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ?",
        (now,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    return [(row["kid"], row["key"], row["exp"]) for row in rows]
