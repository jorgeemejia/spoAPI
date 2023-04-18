import http.server
import socketserver
import mysql.connector
import asyncio
from dbConnection import dbConnection
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

db = dbConnection()

@app.route('/login', methods=['POST'])
async def login():
    data = await request.get_json()
    username = data['username']
    password = data['password']
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE userName=%s AND userPassword=%s", (username, password))
    user = cursor.fetchone()
    if user:
        userPublic = user[2]
        return jsonify({'success': True, 'userPublic': userPublic})
    else:
        return jsonify({'success': False})
    
if __name__ == '__main__':
    PORT = 3001
    app.run(port=PORT, threaded=True)
    print("Server running on port 3001")