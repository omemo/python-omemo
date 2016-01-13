# -*- coding: utf-8 -*-
#
# Copyright 2015 Bahtiar `kalkin-` Gadimov <bahtiar@gadimov.de>
# Copyright 2015 Daniel Gultsch <daniel@cgultsch.de>
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

from .db_helpers import table_exists, user_version


class EncryptionState():
    """ Used to store if OMEMO is enabled or not between gajim restarts """

    def __init__(self, dbConn):
        """
        :type dbConn: Connection
        """
        self.dbConn = migrate(dbConn)

    def activate(self, jid):
        q = """INSERT OR REPLACE INTO encryption_state (jid, encryption)
               VALUES (?, 1) """

        c = self.dbConn.cursor()
        c.execute(q, (jid, ))
        self.dbConn.commit()

    def deactivate(self, jid):
        q = """INSERT OR REPLACE INTO encryption_state (jid, encryption)
               VALUES (?, 0)"""

        c = self.dbConn.cursor()
        c.execute(q, (jid, ))
        self.dbConn.commit()

    def is_active(self, jid):
        q = 'SELECT encryption FROM encryption_state where jid = ?;'
        c = self.dbConn.cursor()
        c.execute(q, (jid, ))
        result = c.fetchone()
        if result is None:
            return False
        return result[0] == 1


def migrate(dbConn):
    """ Creates the encryption_state table and migrates it if needed.
    """
    if user_version(dbConn) == 0:
        create_table = """ CREATE TABLE encryption_state (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            jid TEXT UNIQUE,
                            encryption INTEGER,
                            timestamp NUMBER DEFAULT CURRENT_TIMESTAMP
                            );
                        """

        if table_exists(dbConn, 'encryption_state'):
            # Given a database which already has `encryption_state` and has
            # `user_version` 0, we assume the database needs migration and
            # migrate it to add an `ID INTEGER AUTOINCREMENT` column
            migrate_sql = """
            BEGIN TRANSACTION;
            ALTER TABLE encryption_state RENAME TO encryption_state_back;
            %s
            INSERT INTO encryption_state(jid, encryption, timestamp)
                SELECT jid, encryption, timestamp FROM encryption_state_back;
            DROP TABLE encryption_state_back;
            PRAGMA user_version=1;
            END TRANSACTION ;
            """ % (create_table)
            dbConn.executescript(migrate_sql)
        else:
            # The database has `user_version` 0 and has no `encryption_state
            # table, so crate it!
            dbConn.executescript(""" BEGIN TRANSACTION;
                                     %s
                                     PRAGMA user_version=1;
                                     END TRANSACTION;
                                 """ % (create_table))

    return dbConn
