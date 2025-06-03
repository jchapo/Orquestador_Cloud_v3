#!/bin/bash
# Script para arreglar el Auth Service

echo "=== Arreglando Auth Service ==="

# 1. Matar procesos auth service existentes
echo "1. Matando procesos auth service existentes..."
sudo pkill -f "auth_service.py"
sleep 2

# 2. Verificar que no hay procesos en puerto 5001
echo "2. Verificando puerto 5001..."
sudo netstat -tlnp | grep :5001 || echo "Puerto 5001 libre"

# 3. Verificar el archivo auth_service.py actual
echo "3. Verificando auth_service.py..."
if [ -f "/opt/pucp-orchestrator/auth_service/auth_service.py" ]; then
    echo "✓ Archivo existe"
    # Verificar si tiene los endpoints correctos
    grep -n "'/login'" /opt/pucp-orchestrator/auth_service/auth_service.py || echo "⚠ Endpoint /login no encontrado"
    grep -n "'/register'" /opt/pucp-orchestrator/auth_service/auth_service.py || echo "⚠ Endpoint /register no encontrado"
else
    echo "✗ Archivo no encontrado"
fi

# 4. Verificar la base de datos
echo "4. Verificando base de datos..."
sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db "SELECT username, role FROM users;" 2>/dev/null || echo "Error leyendo usuarios"

# 5. Probar crear un usuario directamente en la DB para debug
echo "5. Creando usuario de prueba en DB..."
sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db "
INSERT OR REPLACE INTO users (username, password, email, role) 
VALUES ('testuser', 'testpass123', 'test@pucp.edu.pe', 'student');
" 2>/dev/null && echo "✓ Usuario testuser creado" || echo "Error creando usuario"

# 6. Crear un auth service simple y funcional
echo "6. Creando auth service simplificado..."
cat > /opt/pucp-orchestrator/auth_service/auth_service_simple.py << 'EOF'
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
EOF

chmod +x /opt/pucp-orchestrator/auth_service/auth_service_simple.py

# 7. Hacer backup del auth service original y usar el simple
echo "7. Reemplazando auth service..."
cp /opt/pucp-orchestrator/auth_service/auth_service.py /opt/pucp-orchestrator/auth_service/auth_service_backup.py
cp /opt/pucp-orchestrator/auth_service/auth_service_simple.py /opt/pucp-orchestrator/auth_service/auth_service.py

# 8. Inicializar la base de datos
echo "8. Inicializando base de datos..."
cd /opt/pucp-orchestrator/auth_service
python3 -c "
import sqlite3
conn = sqlite3.connect('auth_service.db')
conn.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'student'
)''')
conn.execute(\"INSERT OR REPLACE INTO users (username, password, email, role) VALUES ('admin', 'admin123', 'admin@pucp.edu.pe', 'admin')\")
conn.execute(\"INSERT OR REPLACE INTO users (username, password, email, role) VALUES ('testuser', 'testpass123', 'test@pucp.edu.pe', 'student')\")
conn.commit()
print('✓ Base de datos inicializada')
"

# 9. Iniciar el auth service
echo "9. Iniciando auth service..."
cd /opt/pucp-orchestrator/auth_service
source /opt/pucp-orchestrator/venv/bin/activate
python3 auth_service.py &
AUTH_PID=$!
echo "Auth service iniciado con PID: $AUTH_PID"

# 10. Esperar y probar
echo "10. Esperando que el servicio esté listo..."
sleep 5

echo "11. Probando auth service..."
curl -s http://localhost:5001/health | python3 -m json.tool

echo ""
echo "12. Probando login..."
curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' | python3 -m json.tool

echo ""
echo "=== Auth Service listo ==="
echo "Para matar el proceso: kill $AUTH_PID"

