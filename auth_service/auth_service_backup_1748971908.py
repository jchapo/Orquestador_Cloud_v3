#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'pucp-cloud-secret-2025'

def get_db():
    conn = sqlite3.connect('/opt/pucp-orchestrator/auth_service/auth_service.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL DEFAULT 'student'
        )
    ''')
    
    # Crear usuarios por defecto
    try:
        db.execute("INSERT OR REPLACE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                  ('admin', 'admin123', 'admin@pucp.edu.pe', 'admin'))
        db.execute("INSERT OR REPLACE INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                  ('testuser', 'testpass123', 'test@pucp.edu.pe', 'student'))
        db.commit()
        print("✓ Usuarios por defecto creados")
    except Exception as e:
        print(f"Error: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'auth'})

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print(f"Login request: {data}")
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 401
            
        if user['password'] != password:
            return jsonify({'error': 'Invalid password'}), 401
        
        # Crear token
        payload = {
            'sub': user['username'],
            'user_id': str(user['id']),
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'email': user['email']
            }
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print(f"Register request: {data}")
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'student')
        
        if not all([username, password, email]):
            return jsonify({'error': 'Username, password and email required'}), 400
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                      (username, password, email, role))
            db.commit()
            return jsonify({'message': 'User registered successfully'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
            
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    print("Starting Auth Service on port 5001...")
    app.run(host='0.0.0.0', port=5001, debug=True)
