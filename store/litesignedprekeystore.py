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

from axolotl.invalidkeyidexception import InvalidKeyIdException
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.state.signedprekeystore import SignedPreKeyStore


class LiteSignedPreKeyStore(SignedPreKeyStore):
    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        dbConn.execute(
            "CREATE TABLE IF NOT EXISTS signed_prekeys (" +
            "_id INTEGER PRIMARY" + " KEY AUTOINCREMENT," +
            "prekey_id INTEGER UNIQUE, timestamp INTEGER, record BLOB);")

    def loadSignedPreKey(self, signedPreKeyId):
        q = "SELECT record FROM signed_prekeys WHERE prekey_id = ?"

        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId, ))

        result = cursor.fetchone()
        if not result:
            raise InvalidKeyIdException("No such signedprekeyrecord! %s " %
                                        signedPreKeyId)

        return SignedPreKeyRecord(serialized=result[0])

    def loadSignedPreKeys(self):
        q = "SELECT record FROM signed_prekeys"

        cursor = self.dbConn.cursor()
        cursor.execute(q, )
        result = cursor.fetchall()
        results = []
        for row in result:
            results.append(SignedPreKeyRecord(serialized=row[0]))

        return results

    def storeSignedPreKey(self, signedPreKeyId, signedPreKeyRecord):
        q = "INSERT INTO signed_prekeys (prekey_id, record) VALUES(?,?)"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId, signedPreKeyRecord.serialize()))
        self.dbConn.commit()

    def containsSignedPreKey(self, signedPreKeyId):
        q = "SELECT record FROM signed_prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId, ))
        return cursor.fetchone() is not None

    def removeSignedPreKey(self, signedPreKeyId):
        q = "DELETE FROM signed_prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (signedPreKeyId, ))
        self.dbConn.commit()
