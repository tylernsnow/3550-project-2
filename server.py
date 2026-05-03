from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import uuid
from argon2 import PasswordHasher
from key_store import load_key, get_valid_keys
from db import store_user, get_user_id, log_auth

#password hashing function imported from argon2 library
pswd_hash = PasswordHasher()

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

"""
Handle HTTP requests. 
   new to project-3: register(), /auth path in do_POST 
POST and GET allowed. 
PUT, PATCH, DELETE, HEAD not allowed, return 405
"""
class MyServer(BaseHTTPRequestHandler):
    #!!!
    #Project 3 (authorization) methods
    # handle register requests
    def register(self):
        try:
            # request JSON format: {"username": "$MyCoolUsername", "email": "$MyCoolEmail"}
            # read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            # send error 400 if body is empty/messed up
            if not body:
                self.send_response(400)
                self.end_headers()
                return
            
            # accept registration details
            data = json.loads(body)

            username = data.get("username")
            email = data.get("email")
            # if body has no user/email, response 400
            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing username or email')
                return
            # generate password (UUIDv4)
            password = str(uuid.uuid4())
            # hash password (Argon2)
            hashed_password = hashed_password = pswd_hash.hash(password)

            # try to store user details + hashed password in DB. 
            registration_status = store_user(username, hashed_password, email)  # this var holds the returned HTTP response code
            # if successful, will return 201
            if(registration_status == 201):
                # return password to user in format: {"password": "$UUIDv4"}
                response = {"password": password}

                self.send_response(201)  # status code "CREATED" is 201
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            else:
                # else, respond with error code
                self.send_response(registration_status)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                if(registration_status == 409):
                    self.wfile.write(b'Username already exists')
                return

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Server error: {str(e)}".encode())
        return
    #!!!

# HTTP REQUEST METHODS:

    #!!!
    # Not allowed methods
    # PUT not allowed, respond with 405
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # PATCH not allowed, respond with 405
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # DELETE not allowed, respond with 405
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    # HEAD not allowed, respond with 405
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    #!!!

    # Allowed methods:
    """
        POST requests server to accept data. accepted paths are /register and /auth. 
        /register path will register a user (calls self.register, which will store user details in DB)
        /auth path will load a private key from the DB, sign JWT with private key if possible. /auth requests
        will be logged in DB.
    """
    def do_POST(self):
        # immediately get timestamp of request (to be logged in DB)
        request_timestamp = datetime.datetime.utcnow().isoformat()

        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        is_expired = 'expired' in params
        if parsed_path.path == "/register":
            # call self's register function 
            self.register()
            return
       
        # handle /auth path
        elif parsed_path.path == "/auth":
            # get length of request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            if not body:
                self.send_response(400)
                self.end_headers()
                return

            data = json.loads(body)

            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'Missing username or password')
                return
            
            token_payload = {
                "user": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            # store data for logs: 
            # request IP of client
            ip = self.client_address[0]
            # look up user id from username in token
            user = get_user_id(username)
            #check if user ID exists, if no send 401
            if user is None:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'User not found')
                return
            # register auth attempt
            log_attempt = log_auth(ip, request_timestamp, user)
            # if log attempt is successful, will return 200 (OK).
            if(log_attempt == 200):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')

            if is_expired:
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            try:
                stored_pem, kid = load_key(expired=is_expired, return_kid=True) #load an expired key
                headers = {"kid": str(kid)}
                if stored_pem is None:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write("No key available".encode("utf-8"))
                    return
            
                loaded_key = serialization.load_pem_private_key(   #convert pem to usable format 
                    stored_pem,
                    password=None
                )
                #headers["kid"] = "goodKID" #replace w/ auto-increment kid system in DB
                #Sign JWT with private key:
                encoded_jwt = jwt.encode(token_payload, loaded_key, algorithm="RS256", headers=headers)
                #wrap JWT in json for gradebot:
                encoded_jwt_str = encoded_jwt if isinstance(encoded_jwt, str) else encoded_jwt.decode("utf-8")
                response = json.dumps({"jwt": encoded_jwt_str}).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                #self.wfile.write(bytes(encoded_jwt, "utf-8"))
                self.wfile.write(response)
                return

            except Exception as e:
                print("Error in do_POST:", e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal server error")
                return

    #read non-expired private keys
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            #store list of keys, each should include kid, key_blob
            keys = {
                "keys": []
            }
            #call function to fetch all keys where exp > now
            valid_keys = get_valid_keys()
            for kid, key_blob in valid_keys:
                private_key = serialization.load_pem_private_key(
                    key_blob,
                    password=None
                )
                #get public key:
                public_key = private_key.public_key()
                #extract numbers:
                numbers = public_key.public_numbers()
                #convert to base64URL
                n_b64 = int_to_base64(numbers.n)
                e_b64 = int_to_base64(numbers.e)

                #Build JWK
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": n_b64,
                    "e": e_b64
                }
                keys["keys"].append(jwk)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return
