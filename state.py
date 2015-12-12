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
from base64 import b64encode

from axolotl.util.keyhelper import KeyHelper

from common import gajim
from plugins.helpers import log

from .store.sqlite.liteaxolotlstore import LiteAxolotlStore

DB_DIR = gajim.gajimpaths.data_root


class OmemoState:
    _COUNT_PREKEYS = 100

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
        own_id = self.store.getLocalRegistrationId()
        assert own_id is not None, \
            "Requested device_id but there is no generated"
        return self.store.getLocalRegistrationId()

    def own_device_id_published(self):
        return str(self.own_device_id) in self.own_devices

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
