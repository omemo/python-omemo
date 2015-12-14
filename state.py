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

import logging
import os
from base64 import b64encode

from axolotl.ecc.djbec import DjbECPublicKey
from axolotl.identitykey import IdentityKey
from axolotl.invalidmessageexception import InvalidMessageException
from axolotl.invalidversionexception import InvalidVersionException
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.util.keyhelper import KeyHelper
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from common import gajim
from plugins.helpers import log_calls

from .store.liteaxolotlstore import LiteAxolotlStore

DB_DIR = gajim.gajimpaths.data_root
log = logging.getLogger('gajim.plugin_system.omemo')


class OmemoState:
    _COUNT_PREKEYS = 100
    session_ciphers = {}

    device_ids = {}
    own_devices = []

    def __init__(self, name):
        self.name = name
        self.db_name = 'omemo_' + name + '.db'
        db_file = os.path.join(DB_DIR, self.db_name)
        log.debug('Opening the DB ' + db_file)
        self.store = LiteAxolotlStore(db_file)

        if self.axolotl_intialiased():
            self._generate_axolotl_keys()

    def axolotl_intialiased(self):
        return self.store.getLocalRegistrationId() is None

    def build_session(self, recipient_id, device_id, bundle_dict):
        sessionBuilder = SessionBuilder(self.store, self.store, self.store,
                                        self.store, recipient_id, device_id)

        registration_id = self.store.getLocalRegistrationId()

        preKeyPublic = DjbECPublicKey(bundle_dict['preKeyPublic'][1:])

        signedPreKeyPublic = DjbECPublicKey(bundle_dict['signedPreKeyPublic'][
            1:])
        identityKey = IdentityKey(DjbECPublicKey(bundle_dict['identityKey'][
            1:]))

        prekey_bundle = PreKeyBundle(
            registration_id, device_id, bundle_dict['preKeyId'], preKeyPublic,
            bundle_dict['signedPreKeyId'], signedPreKeyPublic,
            bundle_dict['signedPreKeySignature'], identityKey)

        sessionBuilder.processPreKeyBundle(prekey_bundle)
        self.get_session_cipher(recipient_id, device_id)

    def _generate_axolotl_keys(self):
        log.info("Generating Axolotl keys for " + self.db_name)
        identityKeyPair = KeyHelper.generateIdentityKeyPair()
        registrationId = KeyHelper.generateRegistrationId()
        preKeys = KeyHelper.generatePreKeys(KeyHelper.getRandomSequence(),
                                            self._COUNT_PREKEYS)
        self.store.storeLocalData(registrationId, identityKeyPair)

        self._save_pre_keys(preKeys)

    def _save_pre_keys(self, preKeys):
        log.debug("Storing prekeys")
        for preKey in preKeys:
            self.store.storePreKey(preKey.getId(), preKey)

    def add_devices(self, name, devices):
        log.debug('Saving devices for ' + name + ' → ' + str(devices))
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
        log.debug(account + ' ⇒ Searching device_ids for contact ' +
                  contact.jid)
        if contact.jid not in self.device_ids:
            log.debug(contact.jid + '¬∈ devices_ids[' + account + ']')
            return None

        log.debug(account + ' ⇒ found device_ids ' + str(self.device_ids[
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

    def decrypt_msg(self, msg_dict):
        own_id = self.own_device_id
        if own_id not in msg_dict['keys']:
            log.warn('OMEMO message does not contain our device key')
            return

        iv = msg_dict['iv']
        sid = msg_dict['sid']
        sender_jid = msg_dict['sender_jid']
        payload = msg_dict['payload']

        encrypted_key = msg_dict['keys'][own_id]

        try:
            key = self.handlePreKeyWhisperMessage(sender_jid, sid,
                                                  encrypted_key)
        except (InvalidVersionException, InvalidMessageException):
            key = self.handleWhisperMessage(sender_jid, sid, encrypted_key)

        result = aes_decrypt(key, iv, payload)
        log.debug("Decrypted msg ⇒ " + result)
        return result

    def create_msg(self, jid, plaintext):
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        encrypted_keys = {}

        devices_list = self.device_list_for(jid)
        if len(devices_list) == 0:
            log.error(self.name + ' → No known devices')
            return

        for dev in devices_list:
            self.get_session_cipher(jid, dev)
        session_ciphers = self.session_ciphers[jid]
        if not session_ciphers:
            log.warn('No session ciphers for ' + jid)
            return

        for rid, cipher in session_ciphers.items():
            try:
                encrypted_keys[rid] = cipher.encrypt(key).serialize()
            except:
                log.warn(self.name + ' → Failed to find key for device ' + str(
                    rid))

        if len(encrypted_keys) == 0:
            log_msg = 'Encrypted keys empty'
            log.error(log_msg)
            raise NoValidSessions(log_msg)

        payload = aes_encrypt(key, iv, plaintext)

        result = {'sid': self.own_device_id,
                  'keys': encrypted_keys,
                  'jid': jid,
                  'iv': iv,
                  'payload': payload}

        log.debug('encrypted message')
        log.debug(result)
        return result

    def device_list_for(self, jid):
        if jid not in self.device_ids:
            return set()
        return set(self.device_ids[jid])

    def find_missing_sessions(self, recipient_id):
        devices_with_sessions = set(self.store.getSubDeviceSessions(
            recipient_id))
        known_devices = self.device_list_for(recipient_id)
        missing_devices = known_devices - devices_with_sessions
        log.debug(self.name + ' → Missing device sessions: ' + str(
            missing_devices))
        return missing_devices

    def find_own_missing_sessions(self, recipient_id):
        devices_with_sessions = set(self.store.getSubDeviceSessions(
            recipient_id))
        known_devices = set(self.own_devices) - {self.own_device_id}
        missing_devices = known_devices - devices_with_sessions
        log.debug(self.name + ' → Missing device sessions: ' + str(
            missing_devices))
        return missing_devices

    def get_session_cipher(self, jid, device_id):
        if jid not in self.session_ciphers:
            self.session_ciphers[jid] = {}

        if device_id not in self.session_ciphers[jid]:
            cipher = SessionCipher(self.store, self.store, self.store,
                                   self.store, jid, device_id)
            self.session_ciphers[jid][device_id] = cipher

        return self.session_ciphers[jid][device_id]

    def handlePreKeyWhisperMessage(self, recipient_id, device_id, key):
        preKeyWhisperMessage = PreKeyWhisperMessage(serialized=key)
        sessionCipher = self.get_session_cipher(recipient_id, device_id)
        key = sessionCipher.decryptPkmsg(preKeyWhisperMessage)
        log.debug('PreKeyWhisperMessage -> ' + str(key))
        return key

    def handleWhisperMessage(self, recipient_id, device_id, key):
        whisperMessage = WhisperMessage(serialized=key)
        sessionCipher = self.get_session_cipher(recipient_id, device_id)
        key = sessionCipher.decryptMsg(whisperMessage)
        log.debug('WhisperMessage -> ' + str(key))
        return key


@log_calls('OmemoPlugin')
def aes_decrypt(key, nonce, payload):
    """ Use AES128 GCM with the given key and iv to decrypt the payload. """
    ciphertext = payload[:-16]
    mac = payload[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mac)
    except ValueError:
        log.error('Could not authenticate the message')
    return plaintext


@log_calls('OmemoPlugin')
def aes_encrypt(key, nonce, plaintext):
    """ Use AES128 GCM with the given key and iv to encrypt the payload. """
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.encrypt(plaintext) + cipher.digest()


class NoValidSessions(Exception):
    pass
