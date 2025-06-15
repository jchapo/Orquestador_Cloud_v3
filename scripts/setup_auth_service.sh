#!/bin/bash

# Crear carpeta destino
mkdir -p /opt/pucp-orchestrator/auth_service
cd /opt/pucp-orchestrator/auth_service

# Crear requirements.txt
cat <<EOF > requirements.txt
flask
flask-cors
pyjwt
EOF

# Crear config.py
cat <<EOF > config.py
SECRET_KEY = "pucp-secret-key"
USERS = {
    "admin": "admin123",
    "user1": "pass1"
}
EOF

# Crear auth_service.py
cat <<EOF > auth_service.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import config

app = Flask(__name__)
CORS(app)

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if config.USERS.get(username) != password:
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Auth service is running"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
EOF

echo "✅ Archivos del Auth Service creados en /opt/pucp-orchestrator/auth_service"
