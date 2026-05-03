#Performs database operations on sqlite DB. Connects to sqlite3 DB and can initialize db, creating tables
import sqlite3

DB_NAME = "totally_not_my_privateKeys.db"

def connect_db():
    return sqlite3.connect(DB_NAME)

#Initialize DB according to project 2 instructions. Creates keys and users tables
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
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    conn.commit()
    conn.close()

def store_user(username, password_hash, email):
    conn = connect_db()
    cursor = conn.cursor()

    #try to insert the username into the users table
    try:
        cursor.execute(
        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                    (username, password_hash, email)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        #return error code to caller
        return 409
    conn.close()
    #if write to DB successful, return 201
    return 201

#lookup user id given username
def get_user_id(username):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()

    return row[0] if row else None

# log auth attempts to DB
def log_auth(ip, request_timestamp, user):
    # log IP address, timestamp of request, and user
    conn = connect_db()
    cursor = conn.cursor()
    # try to log auth request in DB, returns error if already logged
    try:
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)",
                (ip, request_timestamp, user)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        #already logged
        conn.close()
        return 409
    conn.close()
    return 200