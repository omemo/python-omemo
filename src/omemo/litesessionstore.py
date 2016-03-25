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

from axolotl.state.sessionrecord import SessionRecord
from axolotl.state.sessionstore import SessionStore


class LiteSessionStore(SessionStore):
    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = dbConn
        dbConn.execute("CREATE TABLE IF NOT EXISTS sessions (" +
                       "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
                       "recipient_id TEXT," + "device_id INTEGER," +
                       "record BLOB," + "timestamp INTEGER, " +
                       "UNIQUE(recipient_id, device_id));")

    def loadSession(self, recipientId, deviceId):
        q = "SELECT record FROM sessions WHERE recipient_id = ? AND device_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId))
        result = c.fetchone()

        if result:
            return SessionRecord(serialized=result[0])
        else:
            return SessionRecord()

    def getSubDeviceSessions(self, recipientId):
        q = "SELECT device_id from sessions WHERE recipient_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, ))
        result = c.fetchall()

        deviceIds = [r[0] for r in result]
        return deviceIds

    def getDeviceTuples(self):
       q = "SELECT recipient_id, device_id from sessions"
       c = self.dbConn.cursor()
       result = []
       for row in c.execute(q):
           result.append((row[0],row[1]))
       return result 

    def storeSession(self, recipientId, deviceId, sessionRecord):
        self.deleteSession(recipientId, deviceId)

        q = "INSERT INTO sessions(recipient_id, device_id, record) VALUES(?,?,?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId, sessionRecord.serialize()))
        self.dbConn.commit()

    def containsSession(self, recipientId, deviceId):
        q = "SELECT record FROM sessions WHERE recipient_id = ? AND device_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, deviceId))
        result = c.fetchone()

        return result is not None

    def deleteSession(self, recipientId, deviceId):
        q = "DELETE FROM sessions WHERE recipient_id = ? AND device_id = ?"
        self.dbConn.cursor().execute(q, (recipientId, deviceId))
        self.dbConn.commit()

    def deleteAllSessions(self, recipientId):
        q = "DELETE FROM sessions WHERE recipient_id = ?"
        self.dbConn.cursor().execute(q, (recipientId, ))
        self.dbConn.commit()
