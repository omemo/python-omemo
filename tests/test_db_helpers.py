import pytest
import sqlite3
from omemo import db_helpers

def test_table_exists():
    db = sqlite3.connect(':memory:', check_same_thread=False)
    assert not db_helpers.table_exists(db, 'foo')

    db.execute('CREATE TABLE foo (a TEXT, b INTEGER);')
    assert db_helpers.table_exists(db, 'foo')


def test_user_version():
    db = sqlite3.connect(':memory:', check_same_thread=False)
    assert db_helpers.user_version(db) == 0

    db.execute('PRAGMA user_version=1')
    assert db_helpers.user_version(db) == 1

