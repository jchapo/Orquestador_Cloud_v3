#!/usr/bin/env python3
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt
import datetime
import sqlite3
import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025')
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'auth_service.db')

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        
        # Crear tabla compatible con el esquema original
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear usuarios por defecto
        try:
            # Verificar si admin existe
            admin = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
            if not admin:
                db.execute('''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (?, ?, ?, ?)
                ''', ('admin', generate_password_hash('admin123'), 'admin@pucp.edu.pe', 'admin'))
                
            # Crear usuario de prueba
            test_user = db.execute('SELECT id FROM users WHERE username = ?', ('testuser',)).fetchone()
            if not test_user:
                db.execute('''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (?, ?, ?, ?)
                ''', ('testuser', generate_password_hash('testpass123'), 'test@pucp.edu.pe', 'student'))
                
            db.commit()
            logger.info("Default users created successfully")
        except Exception as e:
            logger.error(f"Error creating default users: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'auth',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        logger.info(f"Login attempt for user: {data.get('username') if data else 'No data'}")
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
            
        if not check_password_hash(user['password_hash'], password):
            logger.warning(f"Invalid password for user: {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Crear token JWT
        payload = {
            'sub': user['username'],
            'user_id': str(user['id']),
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        logger.info(f"Successful login for user: {username}")
        
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
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        logger.info(f"Registration attempt for user: {data.get('username') if data else 'No data'}")
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        role = data.get('role', 'student')
        
        if not all([username, password, email]):
            return jsonify({'error': 'Username, password and email are required'}), 400
        
        db = get_db()
        try:
            db.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, generate_password_hash(password), email, role))
            db.commit()
            
            logger.info(f"User registered successfully: {username}")
            return jsonify({'message': 'User registered successfully'}), 201
            
        except sqlite3.IntegrityError:
            logger.warning(f"Registration failed - user exists: {username}")
            return jsonify({'error': 'Username or email already exists'}), 409
            
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/validate', methods=['POST'])
def validate_token():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'valid': False, 'error': 'Missing token'}), 401
        
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        return jsonify({
            'valid': True,
            'user': {
                'username': payload['sub'],
                'user_id': payload['user_id'],
                'role': payload['role']
            }
        })
        
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return jsonify({'valid': False, 'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    logger.info("Starting Auth Service on port 5001...")
    app.run(host='0.0.0.0', port=5001, debug=False)
