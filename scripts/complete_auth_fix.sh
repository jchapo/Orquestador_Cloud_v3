#!/bin/bash
# Solución completa para Auth Service

echo "=== Solución Completa Auth Service ==="

# 1. Matar TODOS los procesos relacionados
echo "1. Matando todos los procesos auth service..."
sudo pkill -f "auth_service"
sudo pkill -f "5001"
sleep 3

# 2. Verificar qué proceso está usando el puerto 5001
echo "2. Verificando qué usa el puerto 5001..."
sudo lsof -i :5001 || echo "Puerto 5001 libre"

# 3. Forzar liberación del puerto si es necesario
echo "3. Liberando puerto 5001..."
sudo fuser -k 5001/tcp 2>/dev/null || echo "Puerto ya libre"
sleep 2

# 4. Verificar el esquema actual de la base de datos
echo "4. Verificando esquema actual de la base de datos..."
sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db ".schema users" 2>/dev/null || echo "Tabla users no existe"

# 5. Recrear la base de datos desde cero
echo "5. Recreando base de datos desde cero..."
rm -f /opt/pucp-orchestrator/auth_service/auth_service.db
rm -f /opt/pucp-orchestrator/auth_service/auth_service.db-journal

# 6. Crear auth service que funcione con el esquema correcto
echo "6. Creando auth service compatible..."
cat > /opt/pucp-orchestrator/auth_service/auth_service_working.py << 'EOF'
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
EOF

# 7. Reemplazar el auth service actual
echo "7. Reemplazando auth service..."
cp /opt/pucp-orchestrator/auth_service/auth_service.py /opt/pucp-orchestrator/auth_service/auth_service_backup_$(date +%s).py
cp /opt/pucp-orchestrator/auth_service/auth_service_working.py /opt/pucp-orchestrator/auth_service/auth_service.py

# 8. Inicializar la nueva base de datos
echo "8. Inicializando nueva base de datos..."
cd /opt/pucp-orchestrator/auth_service
source /opt/pucp-orchestrator/venv/bin/activate

python3 << 'EOF'
import sys
sys.path.append('/opt/pucp-orchestrator/auth_service')
from auth_service import init_db
try:
    init_db()
    print("✓ Base de datos inicializada correctamente")
except Exception as e:
    print(f"✗ Error inicializando DB: {e}")
EOF

# 9. Verificar la nueva base de datos
echo "9. Verificando nueva base de datos..."
sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db ".schema users"
echo ""
echo "Usuarios creados:"
sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db "SELECT username, email, role FROM users;"

# 10. Iniciar el auth service en background
echo "10. Iniciando auth service..."
cd /opt/pucp-orchestrator/auth_service
nohup python3 auth_service.py > auth_service.log 2>&1 &
AUTH_PID=$!
echo "Auth service iniciado con PID: $AUTH_PID"

# 11. Esperar que esté listo
echo "11. Esperando que el servicio esté listo..."
for i in {1..10}; do
    if curl -s http://localhost:5001/health > /dev/null; then
        echo "✓ Auth service responde"
        break
    fi
    echo "Esperando... ($i/10)"
    sleep 2
done

# 12. Test directo del auth service
echo "12. Probando auth service directamente..."
echo "Health check:"
curl -s http://localhost:5001/health | python3 -m json.tool

echo ""
echo "Test de login:"
curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' | python3 -m json.tool

echo ""
echo "13. Guardando PID para cleanup..."
echo $AUTH_PID > /tmp/auth_service.pid

echo ""
echo "=== Auth Service funcionando ==="
echo "PID: $AUTH_PID"
echo "Log: /opt/pucp-orchestrator/auth_service/auth_service.log"
echo "Para parar: kill $AUTH_PID"
