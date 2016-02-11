import os

import pytest

from omemo.aes_gcm import *


@pytest.fixture
def key():
    return os.urandom(16)

@pytest.fixture
def iv():
    return os.urandom(16)

def test_aes_encrypt(key, iv):
    plaintext = bytes(u'Oh Romemo!'.encode())
    ciphertext = aes_encrypt(key, iv, plaintext)
    assert aes_decrypt(key, iv, ciphertext) == plaintext

def test_encrypt():
    plaintext = u'Oh Romemo!'
    (key, iv, payload) = encrypt(plaintext)
    assert decrypt(key, iv, payload) == plaintext
