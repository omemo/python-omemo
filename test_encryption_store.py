import unittest
from store.encryption import EncryptionState
import os
import sqlite3


class TestEncryptionStateStore(unittest.TestCase):

    def setUp(self):
        self.conn = sqlite3.connect('test-db', check_same_thread=False)
        self.e = EncryptionState(self.conn)

    def test_create(self):
        self.assertEquals(self.e.is_active('romeo@example.com'), False)

    def test_enable_encryption(self):
        self.e.activate('romeo@example.com')
        self.assertEquals(self.e.is_active('romeo@example.com'), True)

    def test_disable_encryption(self):
        self.e.activate('romeo@example.com')
        self.assertEquals(self.e.is_active('romeo@example.com'), True)
        self.e.deactivate('romeo@example.com')
        self.assertEquals(self.e.is_active('romeo@example.com'), False)

    def tearDown(self):
        os.remove('test-db')


if __name__ == '__main__':
    unittest.main()
