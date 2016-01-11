# -*- coding: utf-8 -*-
#
# Copyright 2015 Tarek Galal <tare2.galal@gmail.com>
#
# This file is part of Gajim-OMEMO plugin.
#
# The Gajim-OMEMO plugin is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# Gajim-OMEMO is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# the Gajim-OMEMO plugin.  If not, see <http://www.gnu.org/licenses/>.
#

from axolotl.ecc.djbec import DjbECPrivateKey, DjbECPublicKey
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.state.identitykeystore import IdentityKeyStore


class LiteIdentityKeyStore(IdentityKeyStore):
    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        dbConn.execute(
            "CREATE TABLE IF NOT EXISTS identities (" +
            "_id INTEGER PRIMARY KEY AUTOINCREMENT," + "recipient_id TEXT," +
            "registration_id INTEGER, public_key BLOB, private_key BLOB," +
            "next_prekey_id NUMBER, timestamp NUMBER, trust NUMBER);")

    def getIdentityKeyPair(self):
        q = "SELECT public_key, private_key FROM identities " + \
            "WHERE recipient_id = -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchone()

        publicKey, privateKey = result
        return IdentityKeyPair(
            IdentityKey(DjbECPublicKey(publicKey[1:])),
            DjbECPrivateKey(privateKey))

    def getLocalRegistrationId(self):
        q = "SELECT registration_id FROM identities WHERE recipient_id = -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchone()
        return result[0] if result else None

    def storeLocalData(self, registrationId, identityKeyPair):
        q = "INSERT INTO identities( " + \
            "recipient_id, registration_id, public_key, private_key) " + \
            "VALUES(-1, ?, ?, ?)"
        c = self.dbConn.cursor()
        c.execute(q,
                  (registrationId,
                   identityKeyPair.getPublicKey().getPublicKey().serialize(),
                   identityKeyPair.getPrivateKey().serialize()))

        self.dbConn.commit()

    def saveIdentity(self, recipientId, identityKey):
        q = "INSERT INTO identities (recipient_id, public_key) VALUES(?, ?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, identityKey.getPublicKey().serialize()))
        self.dbConn.commit()

    def isTrustedIdentity(self, recipientId, identityKey):
        return True
