import sys
import os
import tempfile
import pytest

ROOT = os.path.abspath(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(scope="function", autouse=True)
def temp_db(monkeypatch):
    """
    Fixture to use a temporary database for each test.
    Automatically applied to all tests (autouse=True).
    """
    # Create a temporary file for the database
    temp_fd, temp_path = tempfile.mkstemp(suffix=".db")
    os.close(temp_fd)  # Close the file descriptor
    
    # Patch the DB_NAME in the database module
    import app.database
    monkeypatch.setattr(app.database, "DB_NAME", temp_path)
    
    yield temp_path
    
    # Cleanup: remove the temporary database file
    try:
        os.unlink(temp_path)
    except OSError:
        pass