import pytest
import sqlite3
from omemo.state import OmemoState

@pytest.fixture
def db():
    """ Open in memory sqlite db and crate a table. """
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    return conn


@pytest.fixture
def omemo_state(db):
    return OmemoState(db)


def test_omemo_state_creation(omemo_state):
    assert isinstance(omemo_state.own_device_id, int)

def test_omemo_state_creation_fails():
    """ This test makes sure you get a proper error pass a wrong object instea
        of a sqlite3.Connection.
    """
    with pytest.raises(AssertionError):
        assert OmemoState("fooo")
    with pytest.raises(AssertionError):
        assert OmemoState(None)
