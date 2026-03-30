from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
#db.py functions:
from db import init_db, insert_key, load_key

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

numbers = private_key.private_numbers()

#insert_key(pem, expiration) #insert the generated valid key into the DB (as text)
#insert_key(expired_pem, expiration) #insert generated expired key into DB

def deserialize_private_key(pem_str):
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None
    )

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

#Handle server HTTP requests. PUT, PATCH, DELETE, HEAD, POST, DELETE
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    #authorization. Load a private key from the DB, sign JWT with private key if possible
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        is_expired = 'expired' in params
        if parsed_path.path == "/auth":
            headers = {
                #"kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if is_expired:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            stored_pem = load_key(expired='is_expired') #load an expired key
            
            if stored_pem is None:
                self.send_response(500)
                self.end_headers
                self.wfile.write("No key available")
                return
            
            loaded_key = serialization.load_pem_private_key(   #convert pem to usable format 
                stored_pem,
                password=None
            )
            headers["kid"] = "goodKID" #replace w/ auto-increment kid system in DB
            #Sign JWT with private key:
            encoded_jwt = jwt.encode(token_payload, loaded_key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    #read non-expired private keys
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            #call function to fetch all keys where exp > now
            #store list of keys, each should include kid, key_blob
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

#host the server. Will host on http://localhost:8080 but this could be changed by just changing hostName&serverPort
if __name__ == "__main__":
    init_db()   #initialize DB: creates table for private keys
    
    #FIXME: put these in a function
    now = int(datetime.datetime.utcnow().timestamp())
    one_hour = now + 3600

    insert_key(pem, one_hour)        # valid key, expires in 1 hour
    insert_key(expired_pem, now)    # expired key, expires now

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
