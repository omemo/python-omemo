import pytest
import sqlite3
from omemo import encryption
from omemo.db_helpers import table_exists, user_version


@pytest.fixture
def db():
    """ Open in memory sqlite db and crate a table. """
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    return conn

def test_downgrade(db):
    """ This test asserts a smooth downgrade of sqlite to pre-3.8.2 version.

        Gajim on Windows and TravisCi use an old sqlite version which does not
        support `WITHOUT ROW ID` which was added in *6bf2187*. This test make sure
        that we can gracefully backup data from the `encryption_state` before
        droping the table and reacreating it with an ID column with
        `AUTO_INCREMENT`.
    """
    q = """ CREATE TABLE encryption_state (
                jid TEXT PRIMARY KEY,
                encryption INTEGER,
                timestamp NUMBER DEFAULT CURRENT_TIMESTAMP
                );
        """
    db.execute(q)
    q = """ SELECT name FROM sqlite_master
            WHERE type='table' AND name='encryption_state';
        """

    encryption.migrate(db)
    assert db is not None
    assert table_exists(db, 'encryption_state')
    assert user_version(db) == 1

def test_fresh_install(db):
    """ Test table creation if the uses never had encryption_state table
        installed (i.e. user skiped gajim-omemo plugin version 0.3)
    """
    assert user_version(db) == 0
    assert not table_exists(db, 'encryption_state')
    encryption.migrate(db)
    assert db is not None
    assert table_exists(db, 'encryption_state')
    assert user_version(db) == 1
