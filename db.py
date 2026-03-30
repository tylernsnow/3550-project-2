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
    kid = cursor.lastrowid #get auto-generated kid
    conn.close()
    return kid

def load_key(expired=False, return_kid=False):
    conn = connect_db()
    cursor = conn.cursor()

    now = int(datetime.datetime.utcnow().timestamp())

    #load a key from the DB
    if expired:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now,)
        )
    else:
        cursor.execute(
            "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1",
            (now,)
        )

    row = cursor.fetchone()
    conn.close()
    if row:
        if return_kid:
            return row[1], row[0]  #kid and key blob
        return row[1]  # just key blob
    return (None, None) if return_kid else None

def get_valid_keys():
    conn = connect_db()
    cursor = conn.cursor()

    now = int(datetime.datetime.utcnow().timestamp())

    cursor.execute(
        "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC",
        (now,)
    )
    rows = cursor.fetchall()

    conn.close()
    return rows
