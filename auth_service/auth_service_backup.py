#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Auth Service (Mejorado)
Maneja autenticación, autorización y gestión de usuarios
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import logging
import uuid
import re

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración mejorada
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025')
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'auth_service.db')
app.config['TOKEN_EXPIRATION_HOURS'] = int(os.getenv('TOKEN_EXPIRATION_HOURS', '24'))
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['LOCKOUT_DURATION_MINUTES'] = 15

# Roles y permisos
ROLES = {
    'admin': ['read', 'write', 'delete', 'manage_users', 'view_all_slices'],
    'professor': ['read', 'write', 'delete', 'view_student_slices'],
    'student': ['read', 'write'],
    'guest': ['read']
}

def get_db():
    """Obtiene conexión a la base de datos con manejo de errores"""
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

def init_db():
    """Inicializa la base de datos con tablas mejoradas"""
    with app.app_context():
        try:
            db = get_db()
            
            # Tabla de usuarios mejorada
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'student',
                    is_active BOOLEAN DEFAULT 1,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL,
                    last_login TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla de sesiones activas
            db.execute('''
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Tabla de auditoría
            db.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            db.commit()
            
            # Crear usuario admin por defecto si no existe
            create_default_admin(db)
            
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise

def create_default_admin(db):
    """Crea usuario admin por defecto"""
    try:
        admin_exists = db.execute(
            'SELECT id FROM users WHERE username = ?', ('admin',)
        ).fetchone()
        
        if not admin_exists:
            admin_id = str(uuid.uuid4())
            db.execute('''
                INSERT INTO users (id, username, password_hash, email, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                admin_id,
                'admin',
                generate_password_hash('admin123'),
                'admin@pucp.edu.pe',
                'admin'
            ))
            db.commit()
            logger.info("Default admin user created")
    except sqlite3.Error as e:
        logger.error(f"Error creating default admin: {e}")

def validate_email(email):
    """Valida formato de email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Valida fortaleza de contraseña"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

def log_audit_event(user_id, action, details, request_obj):
    """Registra evento en auditoría"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO audit_log (id, user_id, action, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            user_id,
            action,
            details,
            request_obj.remote_addr,
            request_obj.headers.get('User-Agent', '')
        ))
        db.commit()
    except Exception as e:
        logger.error(f"Audit logging error: {e}")

def check_rate_limit(username, db):
    """Verifica límite de intentos de login"""
    user = db.execute(
        'SELECT login_attempts, locked_until FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    
    if not user:
        return True, "User not found"
    
    # Verificar si está bloqueado
    if user['locked_until']:
        locked_until = datetime.datetime.fromisoformat(user['locked_until'])
        if datetime.datetime.utcnow() < locked_until:
            minutes_left = (locked_until - datetime.datetime.utcnow()).seconds // 60
            return False, f"Account locked. Try again in {minutes_left} minutes"
        else:
            # Resetear bloqueo
            db.execute(
                'UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?',
                (username,)
            )
            db.commit()
    
    return True, "OK"

def handle_failed_login(username, db):
    """Maneja intento de login fallido"""
    db.execute('''
        UPDATE users 
        SET login_attempts = login_attempts + 1 
        WHERE username = ?
    ''', (username,))
    
    user = db.execute(
        'SELECT login_attempts FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    
    if user and user['login_attempts'] >= app.config['MAX_LOGIN_ATTEMPTS']:
        # Bloquear cuenta
        lockout_until = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=app.config['LOCKOUT_DURATION_MINUTES']
        )
        db.execute('''
            UPDATE users 
            SET locked_until = ? 
            WHERE username = ?
        ''', (lockout_until.isoformat(), username))
    
    db.commit()

def handle_successful_login(user_id, db):
    """Maneja login exitoso"""
    db.execute('''
        UPDATE users 
        SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (user_id,))
    db.commit()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy', 
        'service': 'auth',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/login', methods=['POST'])
def login():
    """Endpoint de login mejorado"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        db = get_db()
        
        # Verificar rate limiting
        can_login, message = check_rate_limit(username, db)
        if not can_login:
            log_audit_event(None, 'LOGIN_BLOCKED', f'Username: {username}, Reason: {message}', request)
            return jsonify({'error': message}), 429
        
        # Buscar usuario
        user = db.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1',
            (username,)
        ).fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            handle_failed_login(username, db)
            log_audit_event(user['id'] if user else None, 'LOGIN_FAILED', f'Username: {username}', request)
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Login exitoso
        handle_successful_login(user['id'], db)
        
        # Generar token
        payload = {
            'sub': user['username'],
            'user_id': user['id'],
            'role': user['role'],
            'permissions': ROLES.get(user['role'], []),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                hours=app.config['TOKEN_EXPIRATION_HOURS']
            )
        }
        
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # Guardar sesión activa
        session_id = str(uuid.uuid4())
        token_hash = generate_password_hash(token)
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(
            hours=app.config['TOKEN_EXPIRATION_HOURS']
        )
        
        db.execute('''
            INSERT INTO active_sessions (id, user_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (session_id, user['id'], token_hash, expires_at.isoformat()))
        db.commit()
        
        log_audit_event(user['id'], 'LOGIN_SUCCESS', f'Username: {username}', request)
        
        return jsonify({
            'token': token,
            'session_id': session_id,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'email': user['email'],
                'permissions': ROLES.get(user['role'], [])
            },
            'expires_in': app.config['TOKEN_EXPIRATION_HOURS'] * 3600
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/register', methods=['POST'])
def register():
    """Endpoint de registro mejorado"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Validar campos requeridos
        required_fields = ['username', 'password', 'email']
        for field in required_fields:
            if not data.get(field, '').strip():
                return jsonify({'error': f'{field} is required'}), 400
        
        username = data['username'].strip().lower()
        password = data['password']
        email = data['email'].strip().lower()
        role = data.get('role', 'student')
        
        # Validaciones
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return jsonify({'error': password_message}), 400
        
        if role not in ROLES:
            return jsonify({'error': 'Invalid role'}), 400
        
        # Verificar duplicados
        db = get_db()
        existing = db.execute('''
            SELECT username, email FROM users 
            WHERE username = ? OR email = ?
        ''', (username, email)).fetchone()
        
        if existing:
            if existing['username'] == username:
                return jsonify({'error': 'Username already exists'}), 409
            else:
                return jsonify({'error': 'Email already exists'}), 409
        
        # Crear usuario
        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)
        
        db.execute('''
            INSERT INTO users (id, username, password_hash, email, role)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, password_hash, email, role))
        db.commit()
        
        log_audit_event(user_id, 'USER_REGISTERED', f'Username: {username}, Role: {role}', request)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user_id,
                'username': username,
                'email': email,
                'role': role
            }
        }), 201
        
    except sqlite3.IntegrityError as e:
        logger.error(f"Database integrity error: {e}")
        return jsonify({'error': 'Username or email already exists'}), 409
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """Endpoint de logout"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Invalidar sesión
        db = get_db()
        token_hash = generate_password_hash(token)
        db.execute('''
            DELETE FROM active_sessions 
            WHERE token_hash = ?
        ''', (token_hash,))
        db.commit()
        
        return jsonify({'message': 'Logged out successfully'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/validate', methods=['POST'])
def validate_token():
    """Valida token JWT"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'valid': False, 'error': 'Missing token'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Verificar si la sesión está activa
            db = get_db()
            user = db.execute(
                'SELECT * FROM users WHERE id = ? AND is_active = 1',
                (payload['user_id'],)
            ).fetchone()
            
            if not user:
                return jsonify({'valid': False, 'error': 'User not found or inactive'}), 401
            
            return jsonify({
                'valid': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role'],
                    'permissions': ROLES.get(user['role'], [])
                }
            })
            
        except jwt.ExpiredSignatureError:
            return jsonify({'valid': False, 'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'valid': False, 'error': 'Invalid token'}), 401
            
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return jsonify({'valid': False, 'error': 'Internal server error'}), 500

@app.route('/users', methods=['GET'])
def list_users():
    """Lista usuarios (solo admin)"""
    try:
        # Validar token y permisos
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Missing authorization'}), 401
        
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        if 'manage_users' not in ROLES.get(payload['role'], []):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        db = get_db()
        users = db.execute('''
            SELECT id, username, email, role, is_active, last_login, created_at
            FROM users
            ORDER BY created_at DESC
        ''').fetchall()
        
        return jsonify([dict(user) for user in users])
        
    except Exception as e:
        logger.error(f"List users error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5001, debug=False)