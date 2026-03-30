import sqlite3
import datetime

DB_NAME = "totally_not_my_privateKeys.db"

def connect_db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def insert_key(key, exp):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (key, exp)
    )
    conn.commit()
    conn.close()

def load_key(expired=False):
    conn = connect_db()
    cursor = conn.cursor()

    now = int(datetime.datetime.utcnow().timestamp())

    #load a key from the DB
    if expired:
        cursor.execute(
            "SELECT key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]  # this is bytes (BLOB)
    return None
    #cursor.execute("SELECT key_value FROM keys WHERE ___")