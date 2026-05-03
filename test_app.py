import unittest
import sqlite3
import os
import datetime

import db  # your db.py

# If you have hashing functions, import them
# from auth import hash_password, verify_password


class TestDatabase(unittest.TestCase):

    def setUp(self):
        # Ensure DB is initialized
        db.init_db()

        # Clean tables so tests are deterministic
        conn = db.connect_db()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM auth_logs")
        cursor.execute("DELETE FROM users")

        conn.commit()
        conn.close()

    # -------------------------
    # USER REGISTRATION TESTS
    # -------------------------

    def test_store_user_success(self):
        result = db.store_user("alice", "hash123", "alice@example.com")
        self.assertEqual(result, 201)

    def test_store_user_duplicate(self):
        db.store_user("bob", "hash123", "bob@example.com")
        result = db.store_user("bob", "hash456", "bob2@example.com")

        self.assertEqual(result, 409)

    def test_get_user_id(self):
        db.store_user("charlie", "hash", "c@example.com")
        user_id = db.get_user_id("charlie")

        self.assertIsNotNone(user_id)
        self.assertIsInstance(user_id, int)

    def test_get_user_id_not_found(self):
        user_id = db.get_user_id("ghost")
        self.assertIsNone(user_id)

    # -------------------------
    # AUTH LOG TESTS
    # -------------------------

    def test_log_auth_success(self):
        db.store_user("dave", "hash", "d@example.com")
        user_id = db.get_user_id("dave")

        timestamp = datetime.datetime.utcnow().isoformat()

        result = db.log_auth("127.0.0.1", timestamp, user_id)

        self.assertEqual(result, 200)

    def test_log_auth_written(self):
        db.store_user("eve", "hash", "e@example.com")
        user_id = db.get_user_id("eve")

        timestamp = datetime.datetime.utcnow().isoformat()

        db.log_auth("127.0.0.1", timestamp, user_id)

        conn = db.connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT request_ip, user_id FROM auth_logs")
        rows = cursor.fetchall()

        conn.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "127.0.0.1")
        self.assertEqual(rows[0][1], user_id)

    # -------------------------
    # PASSWORD HASH TESTS
    # -------------------------

    def test_password_hash_not_plaintext(self):
        password = "mypassword"

        # Replace with your actual hashing function
        import hashlib
        hashed = hashlib.sha256(password.encode()).hexdigest()

        self.assertNotEqual(password, hashed)

    # -------------------------
    # INTEGRATION TEST
    # -------------------------

    def test_full_flow(self):
        # Simulate register → auth log

        username = "frank"
        email = "frank@example.com"
        password_hash = "hash123"

        # Register
        reg_result = db.store_user(username, password_hash, email)
        self.assertEqual(reg_result, 201)

        # Lookup
        user_id = db.get_user_id(username)
        self.assertIsNotNone(user_id)

        # Log auth
        timestamp = datetime.datetime.utcnow().isoformat()
        log_result = db.log_auth("127.0.0.1", timestamp, user_id)

        self.assertEqual(log_result, 200)

        # Verify log exists
        conn = db.connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM auth_logs WHERE user_id=?", (user_id,))
        count = cursor.fetchone()[0]

        conn.close()

        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()