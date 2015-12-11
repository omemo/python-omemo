# -*- coding: utf-8 -*-
#    otrmodule.py
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

import binascii
import os

from axolotl.util.hexutil import HexUtil
from axolotl.util.keyhelper import KeyHelper

from common import gajim
from plugins.helpers import log

from .store.sqlite.liteaxolotlstore import LiteAxolotlStore

DB_DIR = gajim.gajimpaths.data_root


class OmemoState(object):
    _COUNT_PREKEYS = 100

    def __init__(self, name):
        self.db_name = 'omemo_' + name + '.db'
        db_file = os.path.join(DB_DIR, self.db_name)
        log.info('Opening the DB ' + db_file)
        self.store = LiteAxolotlStore(db_file)

        if self.store.getLocalRegistrationId() is None:
            log.info("Generating Axolotl keys for " + self.db_name)
            identityKeyPair = KeyHelper.generateIdentityKeyPair()
            registrationId = KeyHelper.generateRegistrationId()
            preKeys = KeyHelper.generatePreKeys(KeyHelper.getRandomSequence(),
                                                self._COUNT_PREKEYS)
            signedPreKey = KeyHelper.generateSignedPreKey(
                identityKeyPair, KeyHelper.getRandomSequence(65536))
            self.persistKeys(registrationId, identityKeyPair, preKeys,
                             signedPreKey)
        else:
            identityKeyPair = self.store.getIdentityKeyPair()
            preKeys = self.store.loadPreKeys()

        preKeysDict = {}
        for preKey in preKeys:
            keyPair = preKey.getKeyPair()
            preKeysDict[self.adjustId(preKey.getId())] = self.adjustArray(
                keyPair.getPublicKey().serialize()[1:])

    def persistKeys(self,
                    registrationId,
                    identityKeyPair,
                    preKeys,
                    signedPreKey,
                    fresh=True):

        if fresh:
            self.store.storeLocalData(registrationId, identityKeyPair)
        self.store.storeSignedPreKey(signedPreKey.getId(), signedPreKey)

        log.info("Storing prekeys")
        curr = 0
        for preKey in preKeys:
            self.store.storePreKey(preKey.getId(), preKey)
            curr += 1

    def adjustArray(self, arr):
        return HexUtil.decodeHex(binascii.hexlify(arr))

    def adjustId(self, _id):
        _id = format(_id, 'x')
        zfiller = len(_id) if len(_id) % 2 == 0 else len(_id) + 1
        _id = _id.zfill(zfiller if zfiller > 6 else 6)
        # if len(_id) % 2:
        #     _id = "0" + _id
        return binascii.unhexlify(_id)
