# template_service/template_service.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import json
from functools import wraps
import jwt
from advanced_topology_generator import AdvancedTopologyGenerator, TopologyType, FlavorManager
import uuid
import logging
import traceback


# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pucp-orchestrator/template-service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = 'template_service.db'
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025')

# Topologías predefinidas
PREDEFINED_TEMPLATES = {
    'linear-3': {
        'id': 'linear-3',
        'name': 'Linear 3 Nodes',
        'description': 'Three nodes connected in linear topology',
        'type': 'linear',
        'node_count': 3,
        'default_flavor': 'small'
    },
    'linear-5': {
        'id': 'linear-5', 
        'name': 'Linear 5 Nodes',
        'description': 'Five nodes connected in linear topology',
        'type': 'linear',
        'node_count': 5,
        'default_flavor': 'small'
    },
    'ring-4': {
        'id': 'ring-4',
        'name': 'Ring 4 Nodes',
        'description': 'Four nodes connected in ring topology',
        'type': 'ring', 
        'node_count': 4,
        'default_flavor': 'small'
    },
    'star-5': {
        'id': 'star-5',
        'name': 'Star 5 Nodes', 
        'description': 'Five nodes in star topology',
        'type': 'star',
        'node_count': 5,
        'default_flavor': 'small'
    },
    'mesh-4': {
        'id': 'mesh-4',
        'name': 'Mesh 4 Nodes',
        'description': 'Four nodes in full mesh topology', 
        'type': 'mesh',
        'node_count': 4,
        'default_flavor': 'medium'
    }
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
                topology_type TEXT DEFAULT 'custom',
                node_count INTEGER DEFAULT 3,
                infrastructure TEXT DEFAULT 'linux',
                definition TEXT NOT NULL,
                is_public BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(
                token, 
                app.config['SECRET_KEY'], 
                algorithms=['HS256']
            )
            
            # Configurar usuario actual
            g.current_user = {
                'user_id': payload.get('user_id') or payload.get('sub'),
                'username': payload.get('username') or payload.get('sub'),
                'role': payload.get('role', 'user'),
                'permissions': payload.get('permissions', [])
            }
            
        except jwt.ExpiredSignatureError:
            logger.error("Token has expired")
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Unexpected token error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Inicializar generador
topology_generator = AdvancedTopologyGenerator()

@app.route('/templates', methods=['GET'])
@token_required
def list_templates():
    try:
        # Logging detallado del usuario
        logger.info(f"Processing list_templates for user: {g.current_user}")
        
        db = get_db()
        
        # Plantillas predefinidas
        predefined = []
        for key, template in PREDEFINED_TEMPLATES.items():
            predefined.append({
                'id': key,
                'name': template['name'],
                'description': template['description'],
                'topology_type': template['type'],
                'node_count': template['node_count'],
                'is_predefined': True
            })
        
        # Plantillas personalizadas con manejo de columnas dinámicas
        custom_query = '''
            SELECT 
                id, 
                name, 
                description, 
                COALESCE(topology_type, 'custom') as topology_type, 
                COALESCE(node_count, 3) as node_count, 
                is_public 
            FROM templates 
            WHERE user_id = ? OR is_public = 1
            ORDER BY created_at DESC
        '''
        
        custom = db.execute(custom_query, (g.current_user['user_id'],)).fetchall()
        
        return jsonify({
            'predefined': predefined,
            'custom': [dict(template) for template in custom],
            'topology_types': [
                {'type': 'linear', 'name': 'Linear', 'min_nodes': 2},
                {'type': 'ring', 'name': 'Ring', 'min_nodes': 3}, 
                {'type': 'star', 'name': 'Star', 'min_nodes': 2},
                {'type': 'mesh', 'name': 'Mesh', 'min_nodes': 2},
                {'type': 'custom', 'name': 'Custom', 'min_nodes': 1}
            ],
            'available_flavors': FlavorManager.list_flavors()
        })
        
    except Exception as e:
        logger.error(f"List templates error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Internal server error', 
            'details': str(e)
        }), 500

@app.route('/templates', methods=['POST'])
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

@app.route('/templates/generate', methods=['POST'])
@token_required 
def generate_template():
    """Genera una topología dinámicamente"""
    data = request.get_json()
    
    required = ['topology_type', 'node_count']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields: topology_type, node_count'}), 400
    
    topology_type = data['topology_type']
    node_count = int(data['node_count'])
    flavor = data.get('flavor', 'small')
    infrastructure = data.get('infrastructure', 'linux')
    enable_internet = data.get('enable_internet', False)
    internet_vms = data.get('internet_vms', [])
    
    try:
        # Generar topología usando AdvancedTopologyGenerator
        if topology_type == 'linear':
            topology = topology_generator.create_linear_topology(
                node_count, flavor, 1, enable_internet, internet_vms)
        elif topology_type == 'ring':
            if node_count < 3:
                return jsonify({'error': 'Ring topology requires at least 3 nodes'}), 400
            topology = topology_generator.create_ring_topology(
                node_count, flavor, 1, enable_internet, internet_vms)
        elif topology_type == 'star':
            topology = topology_generator.create_star_topology(
                node_count, flavor, 1, enable_internet, internet_vms)
        elif topology_type == 'mesh':
            topology = topology_generator.create_mesh_topology(
                node_count, flavor, 1, enable_internet, internet_vms)
        else:
            return jsonify({'error': f'Unsupported topology type: {topology_type}'}), 400
        
        # Ajustar infraestructura
        topology['infrastructure'] = infrastructure
        
        return jsonify({
            'topology': topology,
            'slice_format': topology_generator.convert_to_slice_format(topology)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/templates/types', methods=['GET'])
@token_required
def get_topology_types():
    """Lista tipos de topología disponibles"""
    return jsonify({
        'types': [
            {
                'id': 'linear',
                'name': 'Linear',
                'description': 'Nodes connected in a line',
                'min_nodes': 2,
                'max_nodes': 20
            },
            {
                'id': 'ring', 
                'name': 'Ring',
                'description': 'Nodes connected in a circle',
                'min_nodes': 3,
                'max_nodes': 15
            },
            {
                'id': 'star',
                'name': 'Star', 
                'description': 'Central node connected to all others',
                'min_nodes': 2,
                'max_nodes': 10
            },
            {
                'id': 'mesh',
                'name': 'Mesh',
                'description': 'All nodes connected to all others', 
                'min_nodes': 2,
                'max_nodes': 8
            }
        ],
        'flavors': FlavorManager.DEFAULT_FLAVORS,
        'infrastructures': ['linux', 'openstack']
    })

@app.route('/templates/<template_id>', methods=['GET'])
@token_required
def get_template(template_id):
    # Verificar si es predefinido
    if template_id in PREDEFINED_TEMPLATES:
        template_config = PREDEFINED_TEMPLATES[template_id]
        
        # Generar topología predefinida dinámicamente
        try:
            if template_config['type'] == 'linear':
                topology = topology_generator.create_linear_topology(
                    template_config['node_count'], 
                    template_config['default_flavor'])
            elif template_config['type'] == 'ring':
                topology = topology_generator.create_ring_topology(
                    template_config['node_count'],
                    template_config['default_flavor'])
            elif template_config['type'] == 'star':
                topology = topology_generator.create_star_topology(
                    template_config['node_count'],
                    template_config['default_flavor'])
            elif template_config['type'] == 'mesh':
                topology = topology_generator.create_mesh_topology(
                    template_config['node_count'],
                    template_config['default_flavor'])
            
            return jsonify({
                'id': template_id,
                'name': template_config['name'],
                'description': template_config['description'],
                'topology_type': template_config['type'],
                'node_count': template_config['node_count'],
                'is_predefined': True,
                'topology': topology,
                'slice_format': topology_generator.convert_to_slice_format(topology)
            })
            
        except Exception as e:
            return jsonify({'error': f'Error generating predefined topology: {str(e)}'}), 500
   
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
