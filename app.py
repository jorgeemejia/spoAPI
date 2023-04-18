import http.server
import socketserver
import mysql.connector
import asyncio
from dbConnection import dbConnection
from flask import Flask, request, jsonify
from flask_cors import CORS
import ssl
import os

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
        # return jsonify({'success': True, 'userPublic': userPublic})
        response = jsonify({'success': True, 'userPublic': userPublic})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    else:
        # return jsonify({'success': False})
        response = jsonify({'success': True, 'userPublic': userPublic})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response
    
if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    PORT = 3001
    app.run(port=PORT, ssl_context=context)
    print("Server running on port 3001")

