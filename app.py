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
import smtplib
from email.mime.text import MIMEText

#Grab the path to the SSL Certificate file
cert_path = os.path.join(os.getcwd(), 'localhost.pem')
#Grab the path to the SSL Private Key file
key_path = os.path.join(os.getcwd(), 'localhost-key.pem')

#Create a Flask application instance
app = Flask(__name__)
#Enable Cross-Origin Resource Sharing (CORS)
CORS(app, resources={r"/*": {"origins": ["https://localhost:3000"]}})

#Establish a connection the MySql database
db = dbConnection()

"""
The login route 
(1)Gets the username and password from the request
(2)Checks if the user actually is an existing member
(3)Sends a jwt if everything checks out
"""
@app.route('/login', methods=['POST'])
def login():
    #(1) Gets the username and password from the request
    data = request.get_json()
    username = data['username']
    password = data['password']
    #(2)Checks if the user actually is an existing member
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE userName=%s AND userPassword=%s", (username, password))
    user = cursor.fetchone()
    #(3)Sends a jwt if everything checks out
    if user:
        payload = {'username': username}
        secret_key = 'secretkey123'
        algorithm = 'HS256'
        jwt_token = jwt.encode(payload, secret_key, algorithm=algorithm)
        response = jsonify({'success': True, 'jwt' : jwt_token})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    else:
        response = jsonify({'success': False})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

"""
The order route 
(1)Gets the order, timestamp, and digital signature from the request
(2)Grabs the jwt from the authorization headers and extracts the username within
   the jwt
(3)Gets a public key from the db that corresponds to the username
(4)Verifies the digital signature
(5)Verifies the timestamp is fresh(5 minutes)
(6)Checks if the order is in stock
"""
@app.route('/order', methods=['POST'])
def order():
    #(1)Gets the order, timestamp, and digital signature from the request
    data = request.get_json()
    order = data['order']
    timestamp = data['timestamp']
    signature = data['signature']
    #(2)Grabs the jwt from the authorization headers and extracts the username within
    #the jwt
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Authorization token is missing'}), 401
    token = token.split(' ')[1]
    try: 
        payload = jwt.decode(token, 'secretkey123', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Expired token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 401
    username = payload['username']
    #(3)Gets a public key from the db that corresponds to the username
    cursor = db.cursor()
    cursor.execute("SELECT userPublic FROM users WHERE userName=%s", (username,))
    publicKey = cursor.fetchone()
    publicKey = publicKey[0]
    #(4)Verifies the digital signature
    order_bytes = order.encode('utf-8')
    decoded_signature = base64.b64decode(signature)
    public_key = serialization.load_pem_public_key(publicKey.encode(), backend=default_backend())
    try:
        public_key.verify(
            decoded_signature,
            order_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        verified = True
    except InvalidSignature:
        verified = False
    if not verified:
        return jsonify({'message': 'Invalid signature'}), 401
    #(5)Verifies the timestamp is fresh(5 minutes)
    submitted_timestamp = timestamp[:-1]
    current_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")
    submitted_datetime = datetime.strptime(submitted_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    current_datetime = datetime.strptime(current_timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    time_diff = (current_datetime - submitted_datetime).total_seconds()
    if time_diff > 300:
        return jsonify({'message': 'Timestamp is invalid'}), 401
    #(6)Checks if the order is in stock
    cursor.execute("SELECT order_number FROM orders WHERE order_number=%s", (order, ))
    grabbed_order = cursor.fetchone()
    if grabbed_order:
        response = jsonify({'success': True, "order_status:" : "completed"})
        response.headers.add('Access-Control-Allow-Origin', '*')
        #####################################################################
        #TODO CHATGPT, ADD SOME CODE HERE THAT WILL SEND AN EMAIL
        sender_email = 'jorgemejia62100@gmail.com'
        receiver_email = 'jorgemejia62100@gmail.com'
        subject = 'Order Confirmation'
        message = 'Your order has been completed.'

        # Create a MIMEText object with the email content
        email_content = MIMEText(message)
        email_content['Subject'] = subject
        email_content['From'] = sender_email
        email_content['To'] = receiver_email

        # Send the email using SMTP
        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login('jorgemejia62100@gmail.com', 'aahpcesvluxdhayf')
        smtp_server.sendmail(sender_email, receiver_email, email_content.as_string())
        smtp_server.quit()
        #####################################################################
        return response
    else:
        response = jsonify({'success': False, "order_status:" : "unable to complete"})
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
