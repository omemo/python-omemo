import random
import sqlite3
import sys
from base64 import decodestring

import pytest
from axolotl.sessioncipher import SessionCipher

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
    romeo = "romeo@example.com"
    omemo_state.set_own_devices(romeo, devices_update) 
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
    omemo_state.set_own_devices([1, 2, 2, 1]) 
    assert len(omemo_state.own_devices) == 2


def test_own_device_id_published(omemo_state):
    """ :py:method:`OmemoState.own_device_id_published()` should return True
        only if own device id was added via
        :py:method:`OmemoState.set_own_devices()`.
    """
    romeo = "romeo@example.com"
    assert omemo_state.own_device_id_published() == False
    omemo_state.set_own_devices(romeo, [2,3,4,5]) 
    assert omemo_state.own_device_id_published() == False
    omemo_state.set_own_devices(romeo, [omemo_state.own_device_id]) 
    assert omemo_state.own_device_id_published() == True

def test_add_device(omemo_state):
    romeo = "romeo@example.com"
    assert len(omemo_state.device_list_for(romeo)) == 0
    omemo_state.set_devices(romeo, (1,2,3,4))
    assert len(omemo_state.device_list_for(romeo)) == 4

    julia = "julia@example.com"
    assert len(omemo_state.device_list_for(julia)) == 0


@pytest.mark.skipif(True, reason="NOT IMPLEMENTED")
def test_device_list_tupple(omemo_state):
    name = "romeo@example.com"
    omemo_state.set_devices(name, (1,2,3,4))
    assert isinstance(omemo_state.device_list_for(name), tuple) 

def test_device_list_duplicate_handling(omemo_state):
    """ Should not save duplicate device ids for the same user """
    name = "romeo@example.com"
    omemo_state.set_devices(name, [1,2,2,1])
    assert len(omemo_state.device_list_for(name)) == 2

def test_own_devices_without_sessions(omemo_state):
    own_jid = "romeo@example.com"
    assert len(omemo_state.own_devices_without_sessions(own_jid)) == 0
    omemo_state.set_own_devices([1,2,3,4])
    assert len(omemo_state.own_devices_without_sessions(own_jid)) == 4
    

def test_own_devices_without_sessions(omemo_state):
    julia = "julia@example.com"
    assert len(omemo_state.devices_without_sessions(julia)) == 0
    omemo_state.set_devices(julia, [1,2,3,4])
    assert len(omemo_state.devices_without_sessions(julia)) == 4

def test_bundle(omemo_state):
    bundle = omemo_state.bundle
    assert isinstance(bundle, dict)
    assert isinstance(bundle['identityKey'], bytes)
    assert isinstance(bundle['prekeys'], list)
    for f in bundle['prekeys']:
        preKeyId, preKeyPublic = f
        assert isinstance(preKeyId, int)
        assert isinstance(preKeyPublic, bytes)
    assert isinstance(bundle['signedPreKeyId'], int)
    assert isinstance(bundle['signedPreKeyPublic'], bytes)
    assert isinstance(bundle['signedPreKeySignature'], bytes)


def test_build_session():
    romeo = omemo_state(db())
    julia = omemo_state(db())

    assert romeo
    assert julia

    romeo_device = romeo.own_device_id

    bundle = romeo.bundle
    assert isinstance(bundle, dict)
    julias_session = julia.build_session("romeo@example.com", romeo_device,
            bundle)
    assert isinstance(julias_session, SessionCipher)

def test_create_message():
    romeo = omemo_state(db())
    julia = omemo_state(db())
    r_jid ="romeo@example.com"
    j_jid = "julia@example.com"

    romeo_device = romeo.own_device_id

    bundle = romeo.bundle
    julia.build_session(r_jid, romeo_device, bundle)
    msg_dict = julia.create_msg(j_jid, r_jid, "Oh Romeo!")
    assert isinstance(msg_dict, dict)
    assert msg_dict['jid'] == r_jid
    assert decodestring(msg_dict['iv'])
    assert decodestring(msg_dict['payload'])
    for rid, key in msg_dict['keys'].items():
        assert isinstance(rid, int)
        assert decodestring(key)


def test_decrypt_message():
    romeo = omemo_state(db())
    julia = omemo_state(db())
    r_jid ="romeo@example.com"
    j_jid = "julia@example.com"

    romeo_device = romeo.own_device_id

    bundle = romeo.bundle
    julia.build_session(r_jid, romeo_device, bundle)
    msg_dict = julia.create_msg(j_jid, r_jid, "Oh Romeo!")
    msg_dict['sender_jid'] = j_jid
    assert romeo.decrypt_msg(msg_dict) == "Oh Romeo!"

