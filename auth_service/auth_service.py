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
