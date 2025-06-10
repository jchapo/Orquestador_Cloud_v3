#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Slice Service (Mejorado)
Maneja creación, gestión y despliegue de slices con VM Placement (R4)
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import uuid
import datetime
import json
import requests
import logging
from functools import wraps
from typing import Dict, List, Any, Optional
import jwt

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'slice_service.db')
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025')
app.config['LINUX_DRIVER_URL'] = os.getenv('LINUX_DRIVER_URL', 'http://localhost:6001')
app.config['OPENSTACK_DRIVER_URL'] = os.getenv('OPENSTACK_DRIVER_URL', 'http://localhost:6002')
app.config['RESOURCE_MANAGER_URL'] = os.getenv('RESOURCE_MANAGER_URL', 'http://localhost:6003')

# VM Flavors disponibles
VM_FLAVORS = {
    'nano': {'vcpus': 1, 'ram': 512, 'disk': 1},
    'micro': {'vcpus': 1, 'ram': 1024, 'disk': 5},
    'small': {'vcpus': 2, 'ram': 2048, 'disk': 10},
    'medium': {'vcpus': 2, 'ram': 4096, 'disk': 20},
    'large': {'vcpus': 4, 'ram': 8192, 'disk': 40}
}

# Estados de slice
SLICE_STATES = [
    'draft', 'validating', 'deploying', 'active', 
    'stopping', 'stopped', 'error', 'deleted'
]

def get_db():
    """Obtiene conexión a la base de datos"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos con esquema mejorado"""
    with app.app_context():
        db = get_db()
        
        # Tabla principal de slices
        db.execute('''
            CREATE TABLE IF NOT EXISTS slices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                template_id TEXT,
                infrastructure TEXT NOT NULL CHECK (infrastructure IN ('linux', 'openstack')),
                availability_zone TEXT,
                status TEXT NOT NULL DEFAULT 'draft',
                placement_policy TEXT DEFAULT 'balanced',
                total_vcpus INTEGER DEFAULT 0,
                total_ram INTEGER DEFAULT 0,
                total_disk INTEGER DEFAULT 0,
                deployment_data TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deployed_at TIMESTAMP,
                deleted_at TIMESTAMP
            )
        ''')
        
        # Tabla de nodos con más detalles
        db.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                slice_id TEXT NOT NULL,
                name TEXT NOT NULL,
                image TEXT NOT NULL,
                flavor TEXT NOT NULL,
                assigned_host TEXT,
                vm_id TEXT,
                ip_address TEXT,
                status TEXT DEFAULT 'pending',
                console_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (slice_id) REFERENCES slices (id) ON DELETE CASCADE
            )
        ''')
        
        # Tabla de redes
        db.execute('''
            CREATE TABLE IF NOT EXISTS slice_networks (
                id TEXT PRIMARY KEY,
                slice_id TEXT NOT NULL,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                vlan_id INTEGER,
                gateway TEXT,
                dns_servers TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (slice_id) REFERENCES slices (id) ON DELETE CASCADE
            )
        ''')
        
        # Tabla de conexiones entre nodos
        db.execute('''
            CREATE TABLE IF NOT EXISTS node_connections (
                id TEXT PRIMARY KEY,
                slice_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                network_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (slice_id) REFERENCES slices (id) ON DELETE CASCADE,
                FOREIGN KEY (source_node_id) REFERENCES nodes (id),
                FOREIGN KEY (target_node_id) REFERENCES nodes (id),
                FOREIGN KEY (network_id) REFERENCES slice_networks (id)
            )
        ''')
        
        # Tabla de zonas de disponibilidad
        db.execute('''
            CREATE TABLE IF NOT EXISTS availability_zones (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                infrastructure TEXT NOT NULL,
                description TEXT,
                max_vcpus INTEGER DEFAULT 100,
                max_ram INTEGER DEFAULT 102400,
                max_disk INTEGER DEFAULT 1000,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla de recursos de servidores
        db.execute('''
            CREATE TABLE IF NOT EXISTS server_resources (
                id TEXT PRIMARY KEY,
                hostname TEXT UNIQUE NOT NULL,
                infrastructure TEXT NOT NULL,
                availability_zone TEXT,
                total_vcpus INTEGER NOT NULL,
                used_vcpus INTEGER DEFAULT 0,
                total_ram INTEGER NOT NULL,
                used_ram INTEGER DEFAULT 0,
                total_disk INTEGER NOT NULL,
                used_disk INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (availability_zone) REFERENCES availability_zones (id)
            )
        ''')
        
        db.commit()
        
        # Crear zonas de disponibilidad por defecto
        create_default_zones(db)
        create_default_servers(db)

def create_default_zones(db):
    """Crea zonas de disponibilidad por defecto"""
    default_zones = [
        ('zone1-linux', 'linux', 'Linux Cluster Zone 1', 50, 51200, 500),
        ('zone2-linux', 'linux', 'Linux Cluster Zone 2', 50, 51200, 500),
        ('zone1-openstack', 'openstack', 'OpenStack Cluster Zone 1', 100, 102400, 1000),
        ('zone2-openstack', 'openstack', 'OpenStack Cluster Zone 2', 100, 102400, 1000)
    ]
    
    for zone_name, infra, desc, vcpus, ram, disk in default_zones:
        existing = db.execute('SELECT id FROM availability_zones WHERE name = ?', (zone_name,)).fetchone()
        if not existing:
            db.execute('''
                INSERT INTO availability_zones (id, name, infrastructure, description, max_vcpus, max_ram, max_disk)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), zone_name, infra, desc, vcpus, ram, disk))
    
    db.commit()

def create_default_servers(db):
    """Crea servidores por defecto basados en el proyecto"""
    default_servers = [
        # Linux cluster servers
        ('server1', 'linux', 'zone1-linux', 8, 16384, 100),
        ('server2', 'linux', 'zone1-linux', 8, 16384, 100),
        ('server3', 'linux', 'zone2-linux', 8, 16384, 100),
        ('server4', 'linux', 'zone2-linux', 8, 16384, 100),
        # OpenStack cluster servers
        ('headnode', 'openstack', 'zone1-openstack', 16, 32768, 200),
        ('worker1', 'openstack', 'zone1-openstack', 12, 24576, 150),
        ('worker2', 'openstack', 'zone2-openstack', 12, 24576, 150),
        ('worker3', 'openstack', 'zone2-openstack', 12, 24576, 150)
    ]
    
    for hostname, infra, zone, vcpus, ram, disk in default_servers:
        existing = db.execute('SELECT id FROM server_resources WHERE hostname = ?', (hostname,)).fetchone()
        if not existing:
            # Obtener zone_id
            zone_row = db.execute('SELECT id FROM availability_zones WHERE name = ?', (zone,)).fetchone()
            zone_id = zone_row['id'] if zone_row else None
            
            db.execute('''
                INSERT INTO server_resources (id, hostname, infrastructure, availability_zone, 
                                            total_vcpus, total_ram, total_disk)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), hostname, infra, zone_id, vcpus, ram, disk))
    
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
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = payload
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def validate_slice_data(data):
    """Valida datos de slice"""
    required = ['name', 'infrastructure', 'nodes', 'networks']
    missing = [field for field in required if field not in data]
    if missing:
        return False, f'Missing required fields: {", ".join(missing)}'
    
    if data['infrastructure'] not in ['linux', 'openstack']:
        return False, 'Infrastructure must be "linux" or "openstack"'
    
    if not data['nodes']:
        return False, 'At least one node is required'
    
    if not data['networks']:
        return False, 'At least one network is required'
    
    # Validar nodos
    for i, node in enumerate(data['nodes']):
        node_required = ['name', 'image', 'flavor']
        node_missing = [field for field in node_required if field not in node]
        if node_missing:
            return False, f'Node {i+1} missing fields: {", ".join(node_missing)}'
        
        if node['flavor'] not in VM_FLAVORS:
            return False, f'Invalid flavor "{node["flavor"]}" for node {i+1}'
    
    # Validar redes
    for i, network in enumerate(data['networks']):
        net_required = ['name', 'cidr']
        net_missing = [field for field in net_required if field not in network]
        if net_missing:
            return False, f'Network {i+1} missing fields: {", ".join(net_missing)}'
    
    return True, None

class VMPlacementEngine:
    """Motor de colocación de VMs (R4)"""
    
    def __init__(self, db):
        self.db = db
    
    def get_available_resources(self, infrastructure: str, zone: str = None) -> List[Dict]:
        """Obtiene recursos disponibles de servidores"""
        query = '''
            SELECT sr.*, az.name as zone_name
            FROM server_resources sr
            LEFT JOIN availability_zones az ON sr.availability_zone = az.id
            WHERE sr.infrastructure = ? AND sr.status = 'active'
        '''
        params = [infrastructure]
        
        if zone:
            query += ' AND az.name = ?'
            params.append(zone)
        
        query += ' ORDER BY sr.hostname'
        
        servers = self.db.execute(query, params).fetchall()
        
        result = []
        for server in servers:
            available = {
                'id': server['id'],
                'hostname': server['hostname'],
                'zone': server['zone_name'],
                'available_vcpus': server['total_vcpus'] - server['used_vcpus'],
                'available_ram': server['total_ram'] - server['used_ram'],
                'available_disk': server['total_disk'] - server['used_disk'],
                'utilization_cpu': (server['used_vcpus'] / server['total_vcpus']) * 100 if server['total_vcpus'] > 0 else 0,
                'utilization_ram': (server['used_ram'] / server['total_ram']) * 100 if server['total_ram'] > 0 else 0,
                'utilization_disk': (server['used_disk'] / server['total_disk']) * 100 if server['total_disk'] > 0 else 0
            }
            result.append(available)
        
        return result
    
    def calculate_placement(self, nodes: List[Dict], infrastructure: str, 
                          zone: str = None, policy: str = 'balanced') -> Dict[str, Any]:
        """Calcula colocación óptima de VMs"""
        
        available_servers = self.get_available_resources(infrastructure, zone)
        
        if not available_servers:
            return {
                'success': False,
                'error': f'No available servers in {infrastructure} infrastructure'
            }
        
        # Calcular recursos totales necesarios
        total_required = {'vcpus': 0, 'ram': 0, 'disk': 0}
        node_requirements = []
        
        for node in nodes:
            flavor = VM_FLAVORS[node['flavor']]
            requirement = {
                'node_name': node['name'],
                'vcpus': flavor['vcpus'],
                'ram': flavor['ram'],
                'disk': flavor['disk']
            }
            node_requirements.append(requirement)
            
            for resource in ['vcpus', 'ram', 'disk']:
                total_required[resource] += requirement[resource]
        
        # Verificar capacidad total
        total_available = {'vcpus': 0, 'ram': 0, 'disk': 0}
        for server in available_servers:
            total_available['vcpus'] += server['available_vcpus']
            total_available['ram'] += server['available_ram']
            total_available['disk'] += server['available_disk']
        
        for resource in ['vcpus', 'ram', 'disk']:
            if total_required[resource] > total_available[resource]:
                return {
                    'success': False,
                    'error': f'Insufficient {resource}: required {total_required[resource]}, available {total_available[resource]}'
                }
        
        # Aplicar algoritmo de colocación según política
        if policy == 'balanced':
            placement = self._balanced_placement(node_requirements, available_servers)
        elif policy == 'consolidated':
            placement = self._consolidated_placement(node_requirements, available_servers)
        elif policy == 'distributed':
            placement = self._distributed_placement(node_requirements, available_servers)
        else:
            placement = self._balanced_placement(node_requirements, available_servers)
        
        return placement
    
    def _balanced_placement(self, nodes: List[Dict], servers: List[Dict]) -> Dict[str, Any]:
        """Colocación balanceada - distribuye carga uniformemente"""
        placement = {}
        
        # Ordenar servidores por utilización (menor a mayor)
        servers_sorted = sorted(servers, key=lambda x: (x['utilization_cpu'] + x['utilization_ram']) / 2)
        
        for node in nodes:
            best_server = None
            best_score = float('inf')
            
            for server in servers_sorted:
                # Verificar si el servidor puede alojar este nodo
                if (server['available_vcpus'] >= node['vcpus'] and
                    server['available_ram'] >= node['ram'] and
                    server['available_disk'] >= node['disk']):
                    
                    # Calcular score (menor es mejor)
                    cpu_util_after = ((server['available_vcpus'] - node['vcpus']) / 
                                    (server['available_vcpus'] + server['available_vcpus'])) * 100
                    ram_util_after = ((server['available_ram'] - node['ram']) / 
                                    (server['available_ram'] + server['available_ram'])) * 100
                    
                    score = abs(cpu_util_after - 50) + abs(ram_util_after - 50)  # Buscar 50% utilización
                    
                    if score < best_score:
                        best_score = score
                        best_server = server
            
            if best_server:
                placement[node['node_name']] = {
                    'server_id': best_server['id'],
                    'hostname': best_server['hostname'],
                    'zone': best_server['zone']
                }
                
                # Actualizar recursos disponibles del servidor
                best_server['available_vcpus'] -= node['vcpus']
                best_server['available_ram'] -= node['ram']
                best_server['available_disk'] -= node['disk']
            else:
                return {
                    'success': False,
                    'error': f'Cannot place node {node["node_name"]} - insufficient resources'
                }
        
        return {'success': True, 'placement': placement}
    
    def _consolidated_placement(self, nodes: List[Dict], servers: List[Dict]) -> Dict[str, Any]:
        """Colocación consolidada - minimiza número de servidores usados"""
        placement = {}
        
        # Ordenar nodos por recursos requeridos (mayor a menor)
        nodes_sorted = sorted(nodes, key=lambda x: x['vcpus'] + x['ram'] + x['disk'], reverse=True)
        
        for node in nodes_sorted:
            best_server = None
            
            # Buscar servidor que ya esté siendo usado
            for server in servers:
                if (server['available_vcpus'] >= node['vcpus'] and
                    server['available_ram'] >= node['ram'] and
                    server['available_disk'] >= node['disk']):
                    
                    # Preferir servidores que ya tienen VMs asignadas
                    server_has_vms = any(p['hostname'] == server['hostname'] for p in placement.values())
                    if server_has_vms or best_server is None:
                        best_server = server
                        if server_has_vms:
                            break
            
            if best_server:
                placement[node['node_name']] = {
                    'server_id': best_server['id'],
                    'hostname': best_server['hostname'],
                    'zone': best_server['zone']
                }
                
                best_server['available_vcpus'] -= node['vcpus']
                best_server['available_ram'] -= node['ram']
                best_server['available_disk'] -= node['disk']
            else:
                return {
                    'success': False,
                    'error': f'Cannot place node {node["node_name"]} - insufficient resources'
                }
        
        return {'success': True, 'placement': placement}
    
    def _distributed_placement(self, nodes: List[Dict], servers: List[Dict]) -> Dict[str, Any]:
        """Colocación distribuida - maximiza disponibilidad"""
        placement = {}
        server_index = 0
        
        for node in nodes:
            placed = False
            attempts = 0
            
            while not placed and attempts < len(servers):
                server = servers[server_index % len(servers)]
                
                if (server['available_vcpus'] >= node['vcpus'] and
                    server['available_ram'] >= node['ram'] and
                    server['available_disk'] >= node['disk']):
                    
                    placement[node['node_name']] = {
                        'server_id': server['id'],
                        'hostname': server['hostname'],
                        'zone': server['zone']
                    }
                    
                    server['available_vcpus'] -= node['vcpus']
                    server['available_ram'] -= node['ram']
                    server['available_disk'] -= node['disk']
                    placed = True
                
                server_index += 1
                attempts += 1
            
            if not placed:
                return {
                    'success': False,
                    'error': f'Cannot place node {node["node_name"]} - insufficient resources'
                }
        
        return {'success': True, 'placement': placement}

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'slice',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/slices', methods=['GET'])
@token_required
def list_slices():
    """Lista slices del usuario"""
    try:
        db = get_db()
        
        # Verificar permisos
        if 'view_all_slices' in g.current_user.get('permissions', []):
            # Admin puede ver todos los slices
            slices = db.execute('''
                SELECT s.*, COUNT(n.id) as node_count
                FROM slices s
                LEFT JOIN nodes n ON s.id = n.slice_id
                WHERE s.deleted_at IS NULL
                GROUP BY s.id
                ORDER BY s.created_at DESC
            ''').fetchall()
        else:
            # Usuario normal ve solo sus slices
            slices = db.execute('''
                SELECT s.*, COUNT(n.id) as node_count
                FROM slices s
                LEFT JOIN nodes n ON s.id = n.slice_id
                WHERE s.user_id = ? AND s.deleted_at IS NULL
                GROUP BY s.id
                ORDER BY s.created_at DESC
            ''', (g.current_user['user_id'],)).fetchall()
        
        result = []
        for slice_row in slices:
            slice_dict = dict(slice_row)
            
            # Obtener estadísticas adicionales
            networks = db.execute('''
                SELECT COUNT(*) as count FROM slice_networks WHERE slice_id = ?
            ''', (slice_row['id'],)).fetchone()
            
            slice_dict['network_count'] = networks['count']
            result.append(slice_dict)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List slices error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices', methods=['POST'])
@token_required
def create_slice():
    """Crea un nuevo slice"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Validar datos
        is_valid, error = validate_slice_data(data)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        slice_id = str(uuid.uuid4())
        db = get_db()
        
        # Calcular recursos totales
        total_vcpus = total_ram = total_disk = 0
        for node in data['nodes']:
            flavor = VM_FLAVORS[node['flavor']]
            total_vcpus += flavor['vcpus']
            total_ram += flavor['ram']
            total_disk += flavor['disk']
        
        try:
            # Insertar slice
            db.execute('''
                INSERT INTO slices (id, user_id, name, description, template_id, 
                                  infrastructure, availability_zone, placement_policy,
                                  total_vcpus, total_ram, total_disk)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                slice_id,
                g.current_user['user_id'],
                data['name'],
                data.get('description'),
                data.get('template_id'),
                data['infrastructure'],
                data.get('availability_zone'),
                data.get('placement_policy', 'balanced'),
                total_vcpus,
                total_ram,
                total_disk
            ))
            
            # Insertar nodos
            for node in data['nodes']:
                db.execute('''
                    INSERT INTO nodes (id, slice_id, name, image, flavor)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    slice_id,
                    node['name'],
                    node['image'],
                    node['flavor']
                ))
            
            # Insertar redes
            for network in data['networks']:
                db.execute('''
                    INSERT INTO slice_networks (id, slice_id, name, cidr, vlan_id, gateway, dns_servers)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    slice_id,
                    network['name'],
                    network['cidr'],
                    network.get('vlan_id'),
                    network.get('gateway'),
                    json.dumps(network.get('dns_servers', []))
                ))
            
            # Insertar conexiones si se especifican
            if 'connections' in data:
                for conn in data['connections']:
                    source_node = db.execute(
                        'SELECT id FROM nodes WHERE slice_id = ? AND name = ?',
                        (slice_id, conn['source'])
                    ).fetchone()
                    
                    target_node = db.execute(
                        'SELECT id FROM nodes WHERE slice_id = ? AND name = ?',
                        (slice_id, conn['target'])
                    ).fetchone()
                    
                    network = db.execute(
                        'SELECT id FROM slice_networks WHERE slice_id = ? AND name = ?',
                        (slice_id, conn['network'])
                    ).fetchone()
                    
                    if source_node and target_node and network:
                        db.execute('''
                            INSERT INTO node_connections (id, slice_id, source_node_id, target_node_id, network_id)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            str(uuid.uuid4()),
                            slice_id,
                            source_node['id'],
                            target_node['id'],
                            network['id']
                        ))
            
            db.commit()
            
            logger.info(f"Slice created: {slice_id} by user {g.current_user['user_id']}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error creating slice: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        return jsonify({
            'id': slice_id,
            'message': 'Slice created successfully',
            'status': 'draft',
            'resources': {
                'total_vcpus': total_vcpus,
                'total_ram': total_ram,
                'total_disk': total_disk
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Create slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>', methods=['GET'])
@token_required
def get_slice(slice_id):
    """Obtiene detalles de un slice"""
    try:
        db = get_db()
        
        # Verificar propiedad o permisos
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND deleted_at IS NULL
        ''', (slice_id,)).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found'}), 404
        
        # Verificar permisos
        if (slice_data['user_id'] != g.current_user['user_id'] and 
            'view_all_slices' not in g.current_user.get('permissions', [])):
            return jsonify({'error': 'Access denied'}), 403
        
        # Obtener nodos
        nodes = db.execute('''
            SELECT * FROM nodes WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        # Obtener redes
        networks = db.execute('''
            SELECT * FROM slice_networks WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        # Obtener conexiones
        connections = db.execute('''
            SELECT nc.*, 
                   sn.name as source_name, 
                   tn.name as target_name,
                   net.name as network_name
            FROM node_connections nc
            JOIN nodes sn ON nc.source_node_id = sn.id
            JOIN nodes tn ON nc.target_node_id = tn.id
            JOIN slice_networks net ON nc.network_id = net.id
            WHERE nc.slice_id = ?
        ''', (slice_id,)).fetchall()
        
        result = dict(slice_data)
        result['nodes'] = [dict(node) for node in nodes]
        result['networks'] = [dict(network) for network in networks]
        result['connections'] = [dict(conn) for conn in connections]
        
        # Parsear datos de despliegue si existen
        if result['deployment_data']:
            try:
                result['deployment_data'] = json.loads(result['deployment_data'])
            except:
                result['deployment_data'] = None
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Get slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>/deploy', methods=['POST'])
@token_required
def deploy_slice(slice_id):
    """Despliega un slice con VM placement"""
    try:
        db = get_db()
        
        # Verificar propiedad del slice
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404
        
        if slice_data['status'] not in ['draft', 'error']:
            return jsonify({'error': f'Cannot deploy slice in status: {slice_data["status"]}'}), 400
        
        # Actualizar estado a 'validating'
        db.execute('''
            UPDATE slices SET status = 'validating', updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (slice_id,))
        db.commit()
        
        # Obtener nodos del slice
        nodes = db.execute('''
            SELECT * FROM nodes WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        if not nodes:
            db.execute('''
                UPDATE slices SET status = 'error', error_message = 'No nodes found'
                WHERE id = ?
            ''', (slice_id,))
            db.commit()
            return jsonify({'error': 'No nodes found in slice'}), 400
        
        # Ejecutar VM Placement
        placement_engine = VMPlacementEngine(db)
        node_list = [dict(node) for node in nodes]
        
        placement_result = placement_engine.calculate_placement(
            node_list,
            slice_data['infrastructure'],
            slice_data['availability_zone'],
            slice_data['placement_policy']
        )
        
        if not placement_result['success']:
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ?
                WHERE id = ?
            ''', (placement_result['error'], slice_id))
            db.commit()
            return jsonify({'error': placement_result['error']}), 400
        
        # Actualizar nodos con asignación de servidores
        for node_name, assignment in placement_result['placement'].items():
            db.execute('''
                UPDATE nodes SET assigned_host = ?, status = 'assigned'
                WHERE slice_id = ? AND name = ?
            ''', (assignment['hostname'], slice_id, node_name))
        
        # Actualizar recursos utilizados en servidores
        for node in node_list:
            if node['name'] in placement_result['placement']:
                assignment = placement_result['placement'][node['name']]
                flavor = VM_FLAVORS[node['flavor']]
                
                db.execute('''
                    UPDATE server_resources 
                    SET used_vcpus = used_vcpus + ?,
                        used_ram = used_ram + ?,
                        used_disk = used_disk + ?,
                        last_updated = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (flavor['vcpus'], flavor['ram'], flavor['disk'], assignment['server_id']))
        
        # Actualizar slice con datos de deployment
        deployment_data = {
            'placement': placement_result['placement'],
            'deployed_at': datetime.datetime.utcnow().isoformat(),
            'infrastructure': slice_data['infrastructure']
        }
        
        db.execute('''
            UPDATE slices 
            SET status = 'deploying', 
                deployment_data = ?,
                deployed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (json.dumps(deployment_data), slice_id))
        
        db.commit()
        
        # Aquí se enviaría la solicitud al driver correspondiente
        # Por ahora simulamos el éxito del deployment
        
        logger.info(f"Slice {slice_id} deployment started with placement: {placement_result['placement']}")
        
        return jsonify({
            'status': 'deployment_started',
            'slice_id': slice_id,
            'placement': placement_result['placement'],
            'message': 'Slice deployment initiated successfully'
        })
        
    except Exception as e:
        logger.error(f"Deploy slice error: {e}")
        # Actualizar estado a error
        try:
            db = get_db()
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ? WHERE id = ?
            ''', (str(e), slice_id))
            db.commit()
        except:
            pass
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/resources', methods=['GET'])
@token_required
def get_resources():
    """Obtiene estado de recursos del sistema (R4)"""
    try:
        db = get_db()
        infrastructure = request.args.get('infrastructure')
        zone = request.args.get('zone')
        
        # Construir query base
        query = '''
            SELECT sr.*, az.name as zone_name,
                   sr.total_vcpus - sr.used_vcpus as available_vcpus,
                   sr.total_ram - sr.used_ram as available_ram,
                   sr.total_disk - sr.used_disk as available_disk
            FROM server_resources sr
            LEFT JOIN availability_zones az ON sr.availability_zone = az.id
            WHERE sr.status = 'active'
        '''
        params = []
        
        if infrastructure:
            query += ' AND sr.infrastructure = ?'
            params.append(infrastructure)
        
        if zone:
            query += ' AND az.name = ?'
            params.append(zone)
        
        query += ' ORDER BY sr.infrastructure, az.name, sr.hostname'
        
        servers = db.execute(query, params).fetchall()
        
        # Obtener zonas de disponibilidad
        zones_query = 'SELECT * FROM availability_zones WHERE is_active = 1'
        if infrastructure:
            zones_query += ' AND infrastructure = ?'
            zones = db.execute(zones_query, [infrastructure]).fetchall()
        else:
            zones = db.execute(zones_query).fetchall()
        
        # Calcular estadísticas por infraestructura
        stats = {}
        for server in servers:
            infra = server['infrastructure']
            if infra not in stats:
                stats[infra] = {
                    'total_servers': 0,
                    'active_servers': 0,
                    'total_vcpus': 0,
                    'used_vcpus': 0,
                    'total_ram': 0,
                    'used_ram': 0,
                    'total_disk': 0,
                    'used_disk': 0
                }
            
            stats[infra]['total_servers'] += 1
            if server['status'] == 'active':
                stats[infra]['active_servers'] += 1
            
            stats[infra]['total_vcpus'] += server['total_vcpus']
            stats[infra]['used_vcpus'] += server['used_vcpus']
            stats[infra]['total_ram'] += server['total_ram']
            stats[infra]['used_ram'] += server['used_ram']
            stats[infra]['total_disk'] += server['total_disk']
            stats[infra]['used_disk'] += server['used_disk']
        
        # Calcular porcentajes de utilización
        for infra in stats:
            s = stats[infra]
            s['cpu_utilization'] = (s['used_vcpus'] / s['total_vcpus'] * 100) if s['total_vcpus'] > 0 else 0
            s['ram_utilization'] = (s['used_ram'] / s['total_ram'] * 100) if s['total_ram'] > 0 else 0
            s['disk_utilization'] = (s['used_disk'] / s['total_disk'] * 100) if s['total_disk'] > 0 else 0
        
        return jsonify({
            'servers': [dict(server) for server in servers],
            'availability_zones': [dict(zone) for zone in zones],
            'statistics': stats,
            'vm_flavors': VM_FLAVORS
        })
        
    except Exception as e:
        logger.error(f"Get resources error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5002, debug=False)
