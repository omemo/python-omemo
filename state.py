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

import os

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

        if self.axolotl_intialiased():
            self._generate_axolotl_keys()

    def axolotl_intialiased(self):
        return self.store.getLocalRegistrationId is None

    def _generate_axolotl_keys(self):
        log.info("Generating Axolotl keys for " + self.db_name)
        identityKeyPair = KeyHelper.generateIdentityKeyPair()
        registrationId = KeyHelper.generateRegistrationId()
        preKeys = KeyHelper.generatePreKeys(KeyHelper.getRandomSequence(),
                                            self._COUNT_PREKEYS)
        signedPreKey = KeyHelper.generateSignedPreKey(
            identityKeyPair, KeyHelper.getRandomSequence(65536))
        self.store.storeLocalData(registrationId, identityKeyPair)
        self.store.storeSignedPreKey(signedPreKey.getId(), signedPreKey)

        self._save_pre_keys(preKeys)

    def _save_pre_keys(self, preKeys):
        log.info("Storing prekeys")
        for preKey in preKeys:
            self.store.storePreKey(preKey.getId(), preKey)
