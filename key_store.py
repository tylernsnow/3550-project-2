#Handles key storing operations. Connects to sqlite3 (through db.py) and executes queries to store and retrieve keys.
#New in project 3: encrypts keys before storing. Decrypts before retrieval
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from db import connect_db

DB_NAME = "totally_not_my_privateKeys.db"

"""
loads the environ var key for AES symmetric encryption/decryption. Program assumes environment variable exists already,
does not generate on its own. To generate key, type export NOT_MY_KEY=$(openssl rand -base64 32) in terminal
"""
def get_crypto_key():
    key_base64 = os.environ.get("NOT_MY_KEY")   #key (base 64)
    if not key_base64: 
        raise ValueError("NOT_MY_KEY environment variable not set")
    
    key = base64.b64decode(key_base64)

    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256")
    
    return key

#encrypt private keys using symmetric AES encryption
def encrypt_private_key(pem_blob): #param: key blob
    key = get_crypto_key()
    aesgcm = AESGCM(key)

    #nonce is random, unique number added to make stored data more private
    nonce = os.urandom(12)  # GCM standard nonce size=12 bytes
    ciphertext = aesgcm.encrypt(nonce, pem_blob, None)

    # Store nonce + ciphertext together
    return nonce + ciphertext

def decrypt_private_key(blob): #param: blob (key in DB)
    key = get_crypto_key()
    aesgcm = AESGCM(key)

    #extract nonce and ciphertext from encrypted blob
    nonce = blob[:12]
    ciphertext = blob[12:]

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

#Inserts a private key into sqlite DB. Parameters: key is actual data of key, exp is expiration
def insert_key(key, exp):
    conn = connect_db()
    cursor = conn.cursor()

    #call to encrypt private key using AES encryption
    encrypted_key = encrypt_private_key(key)

    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (encrypted_key, exp)
    )
    conn.commit()
    kid = cursor.lastrowid #get auto-generated kid
    conn.close()
    return kid

#Loads a private key from sqlite DB. 
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
    decrypted_key = decrypt_private_key(row[1])
    if row:
        if return_kid:
            return decrypted_key, row[0]  #kid and decrypted key blob
        return decrypted_key  # just decrypted key blob
    return (None, None) if return_kid else None

#return non-expired private keys from DB
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