from axolotl.ecc.djbec import DjbECPrivateKey, DjbECPublicKey
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.state.identitykeystore import IdentityKeyStore

from plugins.helpers import log


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
            "next_prekey_id INTEGER, timestamp INTEGER, " +
            "UNIQUE(recipient_id, registration_id));")

    def getIdentityKeyPair(self):
        q = "SELECT public_key, private_key FROM identities " + \
            "WHERE recipient_id = -1"
        c = self.dbConn.cursor()
        c.execute(q)
        result = c.fetchone()

        log.info(result)
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
        q = "DELETE FROM identities WHERE recipient_id=?"
        self.dbConn.cursor().execute(q, (recipientId, ))
        self.dbConn.commit()

        q = "INSERT INTO identities (recipient_id, public_key) VALUES(?, ?)"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, identityKey.getPublicKey().serialize()))
        self.dbConn.commit()

    def isTrustedIdentity(self, recipientId, identityKey):
        return True
        q = "SELECT public_key from identities WHERE recipient_id = ?"
        c = self.dbConn.cursor()
        c.execute(q, (recipientId, ))
        result = c.fetchone()
        if not result:
            return True
        return result[0] == identityKey.getPublicKey().serialize()
