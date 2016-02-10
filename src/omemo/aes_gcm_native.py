from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.modes import GCM


def aes_decrypt(key, iv, payload):
    """ Use AES128 GCM with the given key and iv to decrypt the payload. """
    data = payload[:-16]
    tag = payload[-16:]
    backend = default_backend()
    decryptor = Cipher(
        algorithms.AES(key),
        GCM(iv, tag=tag),
        backend=backend).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def aes_encrypt(key, iv, plaintext):
    """ Use AES128 GCM with the given key and iv to encrypt the plaintext. """
    backend = default_backend()
    encryptor = Cipher(
        algorithms.AES(key),
        GCM(iv),
        backend=backend).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize() + encryptor.tag
