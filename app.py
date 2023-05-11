import asyncio
import ssl
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dbConnection import dbConnection
import jwt
from functools import wraps
import hashlib
import base64
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256 
from cryptography.hazmat.primitives import hashes
import codecs
import base64
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from cryptography.exceptions import InvalidSignature
from datetime import datetime

cert_path = os.path.join(os.getcwd(), 'localhost.pem')
key_path = os.path.join(os.getcwd(), 'localhost-key.pem')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://localhost:3000"]}})

db = dbConnection()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE userName=%s AND userPassword=%s", (username, password))
    user = cursor.fetchone()
    if user:
        userPublic = user[2]
        #create the jwt token
        # payload = {'username': username, 'publicKey' : userPublic}
        payload = {'username': username}
        secret_key = 'secretkey123'
        algorithm = 'HS256'
        jwt_token = jwt.encode(payload, secret_key, algorithm=algorithm)

        response = jsonify({'success': True, 'userPublic': userPublic, 'jwt' : jwt_token})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    else:
        response = jsonify({'success': False})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

@app.route('/order', methods=['POST'])
def order():
    data = request.get_json()
    order = data['order']
    timestamp = data['timestamp']
    signature = data['signature']

    # Extract username from JWT token
    token = request.headers.get('Authorization')
    print("Token: ", token)
    if not token:
        return jsonify({'message': 'Authorization token is missing'}), 401
    token = token.split(' ')[1]
    print("Token: ", token)
    try: 
        payload = jwt.decode(token, 'secretkey123', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!!!!!!'}), 401
    
    username = payload['username']

    

#todo
#gets passed username so keep debugging down the line
#i believe the next hitch would be checking if verification of digital signature work

    # if username:
    #     print(username)
    #     return jsonify({'message': 'Username is here'}), 401

    # Get public key from username in database.users
    cursor = db.cursor()
    cursor.execute("SELECT userPublic FROM users WHERE userName=%s", (username,))
    publicKey = cursor.fetchone()

    #For some reason a tuple is returned so we just get the first element
    publicKey = publicKey[0]
    print("publicKey: ", publicKey)


    print("Order: ", order)

    # Convert the order string to bytes using UTF-8 encoding
    order_bytes = order.encode('utf-8')
    sha256_digest = hashlib.sha256(order_bytes).hexdigest()
    #THE HEX OF ORDER VALUE RECIEVED AND HEX OF ORDER VALUE ON FRONTEND MATCH
    print("Order Hex:", sha256_digest)


    #Omitted turning public key into an object
    #Next, unlock the digest in the digital signature


        # Decode the base64-encoded signature
    decoded_signature = base64.b64decode(signature)

    public_key = serialization.load_pem_public_key(publicKey.encode(), backend=default_backend())

    # Verify the signature and extract the message
    try:
        public_key.verify(
            decoded_signature,
            order_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        message = order_bytes.decode()
        print("Extracted Message:", message)
        verified = True
    except InvalidSignature:
        print("Invalid signature")
        verified = False

    if not verified:
        return jsonify({'message': 'Invalid signature'}), 401
    if verified:
        print("VERIFIED BABY")
        # return jsonify({'message': 'success'}), 201

#TODO VERIFICATION WORKS
#NOW TIME TO CHECK OUT TIMESTAMP


    # Check timestamp within 5 minutes
    submitted_timestamp = timestamp[:-1]  # Remove the 'Z' character
    print("Submitted timestamp:", submitted_timestamp)

    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
    print("Current timestamp (UTC):", current_timestamp)

    submitted_datetime = datetime.strptime(submitted_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    current_datetime = datetime.strptime(current_timestamp, "%Y-%m-%dT%H:%M:%S.%f")

    time_diff = (current_datetime - submitted_datetime).total_seconds()

    if time_diff > 300:
        return jsonify({'message': 'Timestamp is invalid'}), 401


    # Check if order is in the database (perform your database check here)
    cursor.execute("SELECT order_number FROM orders WHERE order_number=%s", (order, ))
    grabbed_order = cursor.fetchone()
    if grabbed_order:
        response = jsonify({'success': True, "order_status:" : True})
        response.headers.add('Access-Control-Allow-Origin', '*')
        print('Order was found')
        return response
    else:
        response = jsonify({'success': False, "order_status:" : False})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
        
    
if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(
        asyncio.gather(
            loop.run_in_executor(None, app.run, 'localhost', 3001, {
                'debug': True,
                'ssl_context': context,
                'use_reloader': False
            })
        )
    )
    print("Server running on port 3001")
