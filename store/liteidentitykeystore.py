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
