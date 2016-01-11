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

from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.state.prekeystore import PreKeyStore


class LitePreKeyStore(PreKeyStore):
    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        dbConn.execute("CREATE TABLE IF NOT EXISTS prekeys(" +
                       "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                       "prekey_id INTEGER UNIQUE, sent_to_server BOOLEAN, " +
                       " record BLOB);")

    def loadPreKey(self, preKeyId):
        q = "SELECT record FROM prekeys WHERE prekey_id = ?"

        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId, ))

        result = cursor.fetchone()
        if not result:
            raise Exception("No such prekeyRecord!")

        return PreKeyRecord(serialized=result[0])

    def loadPendingPreKeys(self):
        q = "SELECT record FROM prekeys"
        cursor = self.dbConn.cursor()
        cursor.execute(q)
        result = cursor.fetchall()

        return [PreKeyRecord(serialized=result[0]) for result in result]
        # return [PreKeyRecord(serialized=result[0]) for r in result]

    def storePreKey(self, preKeyId, preKeyRecord):
        # self.removePreKey(preKeyId)
        q = "INSERT INTO prekeys (prekey_id, record) VALUES(?,?)"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId, preKeyRecord.serialize()))
        self.dbConn.commit()

    def containsPreKey(self, preKeyId):
        q = "SELECT record FROM prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId, ))
        return cursor.fetchone() is not None

    def removePreKey(self, preKeyId):
        q = "DELETE FROM prekeys WHERE prekey_id = ?"
        cursor = self.dbConn.cursor()
        cursor.execute(q, (preKeyId, ))
        self.dbConn.commit()
