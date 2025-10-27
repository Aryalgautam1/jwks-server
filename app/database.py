import sqlite3


DB_NAME = "totally_not_my_privateKeys.db"


def get_db_connection():
    """Get a connection to the database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize the database by creating the keys table if it doesn't exist.
    Uses parameterized SQLite with commits.
    Schema matches P2 requirements:
    - kid: INTEGER PRIMARY KEY AUTOINCREMENT
    - key: BLOB NOT NULL (private key PEM bytes)
    - exp: INTEGER NOT NULL (expiry timestamp)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # P2 Schema: kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB, exp INTEGER
    create_table_query = """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """
    
    cursor.execute(create_table_query)
    conn.commit()
    conn.close()

