import random
import sqlite3
import sys

import pytest

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


def test_own_devices(omemo_state):
    """ Checks the adding/removing device_ids to own_devices .
    """
    assert len(omemo_state.own_devices) == 0
    assert isinstance(omemo_state.own_device_id, int)
    devices_update = [random.randint(0, sys.maxsize) for x in range(0,3)]
    omemo_state.add_own_devices(devices_update) 
    assert len(omemo_state.own_devices) == 3
    assert omemo_state.own_devices == devices_update

@pytest.mark.skipif(True, reason="NOT IMPLEMENTED")
def test_own_device_tupple(omemo_state):
    """ :py:attribute:`own_devices` should be a tupple.
    """
    assert isinstance(omemo_state.own_devices, tuple)


@pytest.mark.skipif(True, reason="NOT IMPLEMENTED")
def test_own_devices_accepts_list(omemo_state):
    """ 
        :py:attribute:`own_devices` should accept a list as argument, but should
         not save duplicates
    """
    omemo_state.add_own_devices([1, 2, 2, 1]) 
    assert len(omemo_state.own_devices) == 2
