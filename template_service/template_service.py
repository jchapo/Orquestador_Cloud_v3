# template_service/template_service.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import json
from functools import wraps
import jwt


app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = 'template_service.db'

# Topologías predefinidas
PREDEFINED_TEMPLATES = {
    'linear-3-nodes': {
        'name': 'Linear 3 Nodes',
        'description': 'Three nodes connected in linear topology',
        'nodes': [
            {'name': 'node1', 'image': 'ubuntu-20.04', 'flavor': 'small'},
            {'name': 'node2', 'image': 'ubuntu-20.04', 'flavor': 'small'},
            {'name': 'node3', 'image': 'ubuntu-20.04', 'flavor': 'small'}
        ],
        'networks': [
            {'name': 'net1', 'cidr': '192.168.1.0/24'},
            {'name': 'net2', 'cidr': '192.168.2.0/24'}
        ],
        'connections': [
            {'source': 'node1', 'target': 'node2', 'network': 'net1'},
            {'source': 'node2', 'target': 'node3', 'network': 'net2'}
        ]
    },
    # Agregar más topologías según sea necesario
}

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS templates (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                definition TEXT NOT NULL,
                is_public BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

def token_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, 'pucp-cloud-secret-2025', algorithms=['HS256'])
            g.current_user = payload
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/templates', methods=['GET'])
@token_required
def list_templates():
    db = get_db()
    
    # Plantillas predefinidas
    predefined = [{
        'id': key,
        'name': value['name'],
        'description': value['description'],
        'is_predefined': True
    } for key, value in PREDEFINED_TEMPLATES.items()]
    
    # Plantillas personalizadas
    custom = db.execute('''
        SELECT id, name, description, is_public 
        FROM templates 
        WHERE user_id = ? OR is_public = 1
    ''', (g.current_user['username'],)).fetchall()
    
    return jsonify({
        'predefined': predefined,
        'custom': [dict(template) for template in custom]
    })

@app.route('/api/templates', methods=['POST'])
@token_required
def create_template():
    data = request.get_json()
    
    required_fields = ['name', 'definition']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        template_id = str(uuid.uuid4())
        db = get_db()
        db.execute('''
            INSERT INTO templates (id, user_id, name, description, definition, is_public)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            template_id,
            g.current_user['username'],
            data['name'],
            data.get('description'),
            json.dumps(data['definition']),
            data.get('is_public', False)
        ))
        db.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify({'id': template_id, 'message': 'Template created successfully'}), 201

@app.route('/api/templates/<template_id>', methods=['GET'])
@token_required
def get_template(template_id):
    # Verificar si es predefinido
    if template_id in PREDEFINED_TEMPLATES:
        return jsonify(PREDEFINED_TEMPLATES[template_id])
    
    # Buscar en templates personalizados
    db = get_db()
    template = db.execute('''
        SELECT * FROM templates 
        WHERE id = ? AND (user_id = ? OR is_public = 1)
    ''', (template_id, g.current_user['username'])).fetchone()
    
    if not template:
        return jsonify({'error': 'Template not found or access denied'}), 404
    
    template_dict = dict(template)
    template_dict['definition'] = json.loads(template_dict['definition'])
    
    return jsonify(template_dict)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'template'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5003)
