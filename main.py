from http.server import HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
#db.py: db initialization
from db import init_db
#key_store.py functions:
from key_store import insert_key
#MyServer object is now in server.py
from server import MyServer

#This will be used in main to host at localhost:8080
hostName = "localhost"
serverPort = 8080

#generate valid private key using rsa system:
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
#generate expired key:
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

#host the server. Will host on http://localhost:8080 but this could be changed by just changing hostName&serverPort
if __name__ == "__main__":
    init_db()   #initialize DB: creates table for private keys
    
    #initialize variables for key expirations. Expired keys could use now or expired
    now = int(datetime.datetime.utcnow().timestamp())
    one_hour = now + 3600
    #expired = now - 3600

    valid_kid = insert_key(pem, one_hour)        # valid key, expires in 1 hour
    expired_kid = insert_key(expired_pem, now)    # expired key, expires now

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
