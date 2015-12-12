# -*- coding: utf-8 -*-
#
# Copyright 2015 Bahtiar `kalkin-` Gadimov <bahtiar@gadimov.de>
#
# This file is part of Gajim.
#
# Gajim is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; version 3 only.
#
# Gajim is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Gajim.  If not, see <http://www.gnu.org/licenses/>.
#

import os
from base64 import b64decode, b64encode

from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
# from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.util.keyhelper import KeyHelper
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from common import gajim
from plugins.helpers import log, log_calls

from .store.sqlite.liteaxolotlstore import LiteAxolotlStore

DB_DIR = gajim.gajimpaths.data_root


class OmemoState:
    _COUNT_PREKEYS = 100
    sessionCiphers = {}

    device_ids = {}
    own_devices = []

    def __init__(self, name):
        self.name = name
        self.db_name = 'omemo_' + name + '.db'
        db_file = os.path.join(DB_DIR, self.db_name)
        log.info('Opening the DB ' + db_file)
        self.store = LiteAxolotlStore(db_file)

        if self.axolotl_intialiased():
            self._generate_axolotl_keys()

        log.info(self.store.getLocalRegistrationId())

    def axolotl_intialiased(self):
        return self.store.getLocalRegistrationId() is None

    def _generate_axolotl_keys(self):
        log.info("Generating Axolotl keys for " + self.db_name)
        identityKeyPair = KeyHelper.generateIdentityKeyPair()
        registrationId = KeyHelper.generateRegistrationId()
        preKeys = KeyHelper.generatePreKeys(KeyHelper.getRandomSequence(),
                                            self._COUNT_PREKEYS)
        self.store.storeLocalData(registrationId, identityKeyPair)

        self._save_pre_keys(preKeys)

    def _save_pre_keys(self, preKeys):
        log.info("Storing prekeys")
        for preKey in preKeys:
            self.store.storePreKey(preKey.getId(), preKey)

    def add_devices(self, name, devices):
        log.info('Saving devices for ' + name + ' → ' + str(devices))
        self.device_ids[name] = devices

    def add_own_devices(self, devices):
        self.own_devices = devices

    @property
    def own_device_id(self):
        reg_id = self.store.getLocalRegistrationId()
        assert reg_id is not None, \
            "Requested device_id but there is no generated"

        return ((reg_id % 2147483646) + 1)

    def own_device_id_published(self):
        return self.own_device_id in self.own_devices

    def device_ids_for(self, contact):
        account = contact.account.name
        log.info(account + ' ⇒ Searching device_ids for contact ' +
                 contact.jid)
        if contact.jid not in self.device_ids:
            log.debug(contact.jid + '¬∈ devices_ids[' + account + ']')
            return None

        log.info(account + ' ⇒ found device_ids ' + str(self.device_ids[
            contact.jid]))
        return self.device_ids[contact.jid]

    @property
    def bundle(self):
        prekeys = [
            (k.getId(), b64encode(k.getKeyPair().getPublicKey().serialize()))
            for k in self.store.loadPreKeys()
        ]

        identityKeyPair = self.store.getIdentityKeyPair()

        signedPreKey = KeyHelper.generateSignedPreKey(
            identityKeyPair, KeyHelper.getRandomSequence(65536))

        self.store.storeSignedPreKey(signedPreKey.getId(), signedPreKey)

        result = {
            'signedPreKeyId': signedPreKey.getId(),
            'signedPreKeyPublic':
            b64encode(signedPreKey.getKeyPair().getPublicKey().serialize()),
            'signedPreKeySignature': b64encode(signedPreKey.getSignature()),
            'identityKey':
            b64encode(identityKeyPair.getPublicKey().serialize()),
            'prekeys': prekeys
        }
        return result

    def decrypt_msg(self, key, iv, payload):
        payload = b64decode(payload)
        iv = b64decode(iv)
        result = aes_decrypt(key, iv, payload)
        log.info("Decrypted msg ⇒ " + result)
        return result

    def encrypt_msg(self, key, iv, plaintext):
        result = aes_encrypt(key, iv, plaintext)
        log.info("Encrypted msg ⇒ " + result)
        return result

    def getSessionCipher(self, recipient_id, device_id):
        if recipient_id in self.sessionCiphers:
            return self.sessionCiphers[recipient_id]
        else:
            self.sessionCiphers[recipient_id] = SessionCipher(
                self.store, self.store, self.store, self.store, recipient_id,
                device_id)
            return self.sessionCiphers[recipient_id]

    def handlePreKeyWhisperMessage(self, recipient_id, device_id, key):
        preKeyWhisperMessage = PreKeyWhisperMessage(serialized=b64decode(key))
        sessionCipher = self.getSessionCipher(recipient_id, device_id)
        key = sessionCipher.decryptPkmsg(preKeyWhisperMessage)
        log.info('PreKeyWhisperMessage -> ' + str(key))
        return key

    def handleWhisperMessage(self, recipient_id, device_id, key):
        log.info(b64decode(key))
        whisperMessage = WhisperMessage(serialized=b64decode(key))
        sessionCipher = self.getSessionCipher(recipient_id, device_id)
        key = sessionCipher.decryptMsg(whisperMessage)
        log.info('WhisperMessage -> ' + str(key))
        return key


@log_calls('OmemoPlugin')
def aes_decrypt(key, iv, payload):
    """ Use AES128 GCM with the given key and iv to decrypt the payload. """
    data = payload[:-16]
    tag = payload[-16:]
    backend = default_backend()
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv,
                  tag=tag),
        backend=backend).decryptor()
    return decryptor.update(data) + decryptor.finalize()


@log_calls('OmemoPlugin')
def aes_encrypt(key, iv, payload):
    """ Use AES128 GCM with the given key and iv to encrypt the payload. """
    backend = default_backend()
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=backend).encryptor()
    return encryptor.update(payload) + encryptor.finalize() + encryptor.tag
