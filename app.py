import asyncio
import ssl
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dbConnection import dbConnection
import jwt

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
        payload = {'username': username, 'publicKey' : userPublic}
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
