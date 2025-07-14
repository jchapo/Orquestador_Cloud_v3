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
from .drivers.linux_driver import LinuxClusterDriver
from .drivers.base_driver import BaseDriver
import ipaddress

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
app.config['SECRET_KEY'] = 'pucp-cloud-secret-2025'
app.config['LINUX_DRIVER_URL'] = os.getenv('LINUX_DRIVER_URL', 'http://localhost:6001')
app.config['OPENSTACK_DRIVER_URL'] = os.getenv('OPENSTACK_DRIVER_URL', 'http://localhost:6002')
app.config['RESOURCE_MANAGER_URL'] = os.getenv('RESOURCE_MANAGER_URL', 'http://localhost:6003')

# VM Flavors disponibles
VM_FLAVORS = {
    'nano': {'vcpus': 1, 'ram': 512, 'disk': 2.5},
    'micro': {'vcpus': 1, 'ram': 1024, 'disk': 5},
    'small': {'vcpus': 1, 'ram': 1536, 'disk': 10},
    'medium': {'vcpus': 2, 'ram': 2560, 'disk': 20},
    'large': {'vcpus': 4, 'ram': 6144, 'disk': 40}
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
        
        # Tabla de nodos CON NUEVOS CAMPOS R5
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
                management_ip TEXT,
                internet_access BOOLEAN DEFAULT 0,
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
                network_type TEXT DEFAULT 'data',
                internet_access BOOLEAN DEFAULT 0,
                is_management BOOLEAN DEFAULT 0,
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

def load_cluster_config():
    """Carga configuración real del cluster PUCP"""
    try:
        with open('/opt/pucp-orchestrator/cluster_config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning("Cluster config not found, using defaults")
        return None
    except Exception as e:
        logger.error(f"Error loading cluster config: {e}")
        return None

def create_default_servers(db):
    """Crea servidores basados en configuración real del cluster PUCP"""
    
    # Intentar cargar configuración real primero
    cluster_config = load_cluster_config()
    
    if cluster_config and 'servers' in cluster_config:
        logger.info("Loading servers from real cluster configuration")
        
        # Usar configuración real del cluster
        for server_name, server_config in cluster_config['servers'].items():
            existing = db.execute('SELECT id FROM server_resources WHERE hostname = ?', (server_name,)).fetchone()
            if not existing:
                # Determinar zona basada en el servidor
                if server_name in ['server1', 'server2']:
                    zone_name = 'zone1-linux'
                elif server_name in ['server3', 'server4']:
                    zone_name = 'zone2-linux'
                else:
                    zone_name = 'zone1-linux'  # fallback
                
                # Obtener zone_id
                zone_row = db.execute('SELECT id FROM availability_zones WHERE name = ?', (zone_name,)).fetchone()
                zone_id = zone_row['id'] if zone_row else None
                
                # Convertir GB a MB para RAM
                ram_mb = server_config['total_ram_mb']
                
                db.execute('''
                    INSERT INTO server_resources (id, hostname, infrastructure, availability_zone, 
                                                total_vcpus, total_ram, total_disk)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), 
                    server_name, 
                    'linux',  # Todos los servidores reales son Linux
                    zone_id, 
                    server_config['total_vcpus'],
                    ram_mb,
                    server_config['total_disk_gb']
                ))
                
                logger.info(f"Added real server: {server_name} ({server_config['total_vcpus']} CPUs, {server_config['total_ram_mb']/1024} GB RAM)")
        
        db.commit()
        logger.info("Real cluster servers loaded successfully")
        
    else:
        # Fallback a configuración por defecto si no hay configuración real
        logger.info("Using default server configuration")
        
        default_servers = [
            # Linux cluster servers (valores por defecto del proyecto)
            ('server1', 'linux', 'zone1-linux', 8, 16384, 100),
            ('server2', 'linux', 'zone1-linux', 8, 16384, 100),
            ('server3', 'linux', 'zone2-linux', 8, 16384, 100),
            ('server4', 'linux', 'zone2-linux', 8, 16384, 100),
            # OpenStack cluster servers (para futuro)
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
        logger.info("Default servers loaded")

def update_real_server_resources(db):
    """Actualiza recursos de servidores con datos reales del cluster"""
    cluster_config = load_cluster_config()
    
    if not cluster_config or 'servers' not in cluster_config:
        logger.warning("No real cluster config available for resource update")
        return
    
    logger.info("Updating server resources with real cluster data")
    
    for server_name, server_config in cluster_config['servers'].items():
        try:
            # Actualizar recursos con datos reales
            ram_mb = server_config['total_ram_mb']
            db.execute('''
                UPDATE server_resources 
                SET total_vcpus = ?, total_ram = ?, total_disk = ?, last_updated = CURRENT_TIMESTAMP
                WHERE hostname = ? AND infrastructure = 'linux'
            ''', (
                server_config['total_vcpus'],
                ram_mb,
                server_config['total_disk_gb'],
                server_name
            ))
            
            logger.info(f"Updated {server_name}: {server_config['total_vcpus']} CPUs, {server_config['total_ram_mb']/1024} GB RAM")
            
        except Exception as e:
            logger.error(f"Error updating server {server_name}: {e}")
    
    db.commit()
    logger.info("Server resources updated with real data")

def get_cluster_status():
    """Obtiene estado actual del cluster real"""
    cluster_config = load_cluster_config()
    
    if not cluster_config:
        return {
            'status': 'unknown',
            'message': 'Cluster configuration not available',
            'servers': 0
        }
    
    active_servers = [
        name for name, config in cluster_config['servers'].items()
        if config.get('status') == 'active'
    ]
    
    return {
        'status': 'operational' if len(active_servers) >= 3 else 'limited',
        'total_servers': len(cluster_config['servers']),
        'active_servers': len(active_servers),
        'cluster_name': cluster_config.get('cluster_name', 'PUCP Cluster'),
        'capacity': cluster_config.get('capacity', {}),
        'last_updated': cluster_config.get('created', 'unknown')
    }

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
    """Valida datos de slice con soporte para R5"""
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
    
    # Validar nodos con nuevos campos R5
    for i, node in enumerate(data['nodes']):
        node_required = ['name', 'image', 'flavor']
        node_missing = [field for field in node_required if field not in node]
        if node_missing:
            return False, f'Node {i+1} missing fields: {", ".join(node_missing)}'
        
        if node['flavor'] not in VM_FLAVORS:
            return False, f'Invalid flavor "{node["flavor"]}" for node {i+1}'
        
        # Validar internet_access (opcional)
        if 'internet_access' in node and not isinstance(node['internet_access'], bool):
            return False, f'Node {i+1}: internet_access must be boolean'
        
        # Validar management_ip (opcional)
        if 'management_ip' in node:
            try:
                ipaddress.IPv4Address(node['management_ip'])
            except ValueError:
                return False, f'Node {i+1}: Invalid management_ip format'
    
    # Validar redes con nuevos campos R5
    for i, network in enumerate(data['networks']):
        net_required = ['name', 'cidr']
        net_missing = [field for field in net_required if field not in network]
        if net_missing:
            return False, f'Network {i+1} missing fields: {", ".join(net_missing)}"'
        
        # Validar network_type (opcional)
        valid_types = ['management', 'trunk', 'data', 'provider']
        if 'network_type' in network and network['network_type'] not in valid_types:
            return False, f'Network {i+1}: Invalid network_type. Must be one of: {valid_types}'
        
        # Validar internet_access (opcional)
        if 'internet_access' in network and not isinstance(network['internet_access'], bool):
            return False, f'Network {i+1}: internet_access must be boolean'
    
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
                # ========== AQUÍ ESTÁ EL PROBLEMA ==========
                # ANTES (INCORRECTO):
                # placement[node['node_name']] = {
                #     'server_id': best_server['id'],
                #     'hostname': best_server['hostname'],  # ← Esto devuelve 'pucp-server2'
                #     'zone': best_server['zone']
                # }
                
                # DESPUÉS (CORRECTO):
                # Mapear hostname de BD a clave de hypervisors
                hostname_mapping = {
                    'pucp-server1': 'server1',
                    'pucp-server2': 'server2',
                    'pucp-server3': 'server3', 
                    'pucp-server4': 'server4'
                }
                
                db_hostname = best_server['hostname']  # 'pucp-server2' de la BD
                driver_hostname = hostname_mapping.get(db_hostname, db_hostname)  # 'server2' para driver
                
                placement[node['node_name']] = {
                    'server_id': best_server['id'],
                    'hostname': driver_hostname,  # ← Ahora devuelve 'server2' 
                    'zone': best_server['zone']
                }
                # ==========================================
                
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

        hostname_mapping = {
            'pucp-server1': 'server1',
            'pucp-server2': 'server2',
            'pucp-server3': 'server3', 
            'pucp-server4': 'server4'
        }
        
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
                db_hostname = best_server['hostname']
                driver_hostname = hostname_mapping.get(db_hostname, db_hostname)
                
                placement[node['node_name']] = {
                    'server_id': best_server['id'],
                    'hostname': driver_hostname,  # ← CORREGIDO
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

        # Mapeo de hostnames
        hostname_mapping = {
            'pucp-server1': 'server1',
            'pucp-server2': 'server2',
            'pucp-server3': 'server3', 
            'pucp-server4': 'server4'
        }
        
        for node in nodes:
            placed = False
            attempts = 0
            
            while not placed and attempts < len(servers):
                server = servers[server_index % len(servers)]
                
                if (server['available_vcpus'] >= node['vcpus'] and
                    server['available_ram'] >= node['ram'] and
                    server['available_disk'] >= node['disk']):
                    
                    db_hostname = server['hostname']
                    driver_hostname = hostname_mapping.get(db_hostname, db_hostname)
                                    
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

def get_driver(infrastructure: str, token: Optional[str] = None) -> BaseDriver:
    if infrastructure == 'linux':
        from .drivers.linux_driver import LinuxClusterDriver
        return LinuxClusterDriver(token=token)
    elif infrastructure == 'openstack':
        from .drivers.openstack_driver import OpenStackDriver
        return OpenStackDriver(token=token)
    else:
        raise ValueError(f"Unsupported infrastructure: {infrastructure}")


@app.route('/validate-integration', methods=['GET'])
@token_required
def validate_integration():
    """Valida integración con Network Service"""
    try:
        # Solo admin puede validar
        if 'admin' not in g.current_user.get('role', ''):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Obtener driver Linux y validar
        driver = get_driver('linux')
        validation_result = driver.validate_network_service_integration()
        
        return jsonify({
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'integration_status': validation_result
        })
        
    except Exception as e:
        logger.error(f"Integration validation error: {e}")
        return jsonify({'error': 'Validation failed'}), 500

@app.route('/slices/<slice_id>/stop', methods=['POST'])
@token_required
def stop_slice(slice_id):
    """Para un slice activo sin eliminarlo"""
    try:
        db = get_db()
        
        # Verificar propiedad del slice
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404
        
        if slice_data['status'] != 'active':
            return jsonify({'error': f'Cannot stop slice in status: {slice_data["status"]}'}), 400
        
        # Actualizar estado a 'stopping'
        db.execute('''
            UPDATE slices SET status = 'stopping', updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (slice_id,))
        db.commit()
        
        try:
            # Obtener VMs del slice
            deployment_data = json.loads(slice_data['deployment_data']) if slice_data['deployment_data'] else {}
            vm_list = deployment_data.get('deployed_vms', [])
            
            if not vm_list:
                # No hay VMs, marcar como stopped directamente
                db.execute('''
                    UPDATE slices SET status = 'stopped', updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (slice_id,))
                db.commit()
                return jsonify({
                    'message': 'Slice stopped successfully (no VMs found)',
                    'slice_id': slice_id,
                    'status': 'stopped'
                })
            
            # Obtener driver y parar VMs
            driver = get_driver(slice_data['infrastructure'])
            
            stopped_vms = []
            errors = []
            
            for vm_info in vm_list:
                try:
                    vm_name = vm_info['name']
                    server_name = vm_info.get('server', vm_info.get('assigned_host'))
                    
                    if not server_name:
                        errors.append(f"No server info for VM {vm_name}")
                        continue
                    
                    # Parar VM (no eliminar)
                    success = driver.stop_vm(vm_name, server_name)
                    if success:
                        stopped_vms.append(vm_name)
                        logger.info(f"✓ VM {vm_name} stopped")
                    else:
                        errors.append(f"Failed to stop VM {vm_name}")
                        
                except Exception as e:
                    error_msg = f"Error stopping VM {vm_info.get('name', 'unknown')}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Actualizar estado final
            final_status = 'stopped' if not errors else 'error'
            error_message = '; '.join(errors) if errors else None
            
            db.execute('''
                UPDATE slices 
                SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (final_status, error_message, slice_id))
            db.commit()
            
            logger.info(f"✓ Slice {slice_id} stopped with status: {final_status}")
            
            return jsonify({
                'status': 'success' if final_status == 'stopped' else 'partial',
                'slice_id': slice_id,
                'final_status': final_status,
                'stopped_vms': stopped_vms,
                'errors': errors,
                'message': f'Slice stop completed with status: {final_status}'
            })
            
        except Exception as e:
            # Error durante el proceso de parada
            db.execute('''
                UPDATE slices 
                SET status = 'error', error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (str(e), slice_id))
            db.commit()
            
            logger.error(f"✗ Critical error stopping slice {slice_id}: {e}")
            return jsonify({'error': 'Internal server error during stop'}), 500
        
    except Exception as e:
        logger.error(f"Critical error in stop_slice: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>/start', methods=['POST'])
@token_required
def start_slice(slice_id):
    """Inicia un slice parado"""
    try:
        db = get_db()
        
        # Verificar propiedad del slice
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404
        
        if slice_data['status'] != 'stopped':
            return jsonify({'error': f'Cannot start slice in status: {slice_data["status"]}'}), 400
        
        # Actualizar estado a 'starting'
        db.execute('''
            UPDATE slices SET status = 'starting', updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (slice_id,))
        db.commit()
        
        try:
            # Obtener información de deployment
            deployment_data = json.loads(slice_data['deployment_data']) if slice_data['deployment_data'] else {}
            vm_list = deployment_data.get('deployed_vms', [])
            
            if not vm_list:
                db.execute('''
                    UPDATE slices 
                    SET status = 'error', error_message = 'No VM deployment data found'
                    WHERE id = ?
                ''', (slice_id,))
                db.commit()
                return jsonify({'error': 'No VM deployment data found'}), 400
            
            # Obtener driver e iniciar VMs
            driver = get_driver(slice_data['infrastructure'])
            
            started_vms = []
            errors = []
            
            for vm_info in vm_list:
                try:
                    vm_name = vm_info['name']
                    server_name = vm_info.get('server', vm_info.get('assigned_host'))
                    
                    if not server_name:
                        errors.append(f"No server info for VM {vm_name}")
                        continue
                    
                    # Iniciar VM
                    success = driver.start_vm(vm_name, server_name)
                    if success:
                        started_vms.append(vm_name)
                        logger.info(f"✓ VM {vm_name} started")
                    else:
                        errors.append(f"Failed to start VM {vm_name}")
                        
                except Exception as e:
                    error_msg = f"Error starting VM {vm_info.get('name', 'unknown')}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Actualizar estado final
            final_status = 'active' if not errors else 'error'
            error_message = '; '.join(errors) if errors else None
            
            db.execute('''
                UPDATE slices 
                SET status = ?, error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (final_status, error_message, slice_id))
            db.commit()
            
            logger.info(f"✓ Slice {slice_id} started with status: {final_status}")
            
            return jsonify({
                'status': 'success' if final_status == 'active' else 'partial',
                'slice_id': slice_id,
                'final_status': final_status,
                'started_vms': started_vms,
                'errors': errors,
                'message': f'Slice start completed with status: {final_status}'
            })
            
        except Exception as e:
            # Error durante el proceso de inicio
            db.execute('''
                UPDATE slices 
                SET status = 'error', error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (str(e), slice_id))
            db.commit()
            
            logger.error(f"✗ Critical error starting slice {slice_id}: {e}")
            return jsonify({'error': 'Internal server error during start'}), 500
        
    except Exception as e:
        logger.error(f"Critical error in start_slice: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>/restart', methods=['POST'])
@token_required
def restart_slice(slice_id):
    """Reinicia un slice activo"""
    try:
        db = get_db()
        
        # Verificar propiedad del slice
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404
        
        if slice_data['status'] not in ['active', 'error']:
            return jsonify({'error': f'Cannot restart slice in status: {slice_data["status"]}'}), 400
        
        # Parar primero
        stop_response = stop_slice(slice_id)
        stop_data = stop_response.get_json()
        
        if stop_data.get('status') != 'success':
            return jsonify({
                'error': 'Failed to stop slice for restart',
                'stop_result': stop_data
            }), 500
        
        # Esperar un momento para que las VMs se paren completamente
        import time
        time.sleep(2)
        
        # Iniciar después
        start_response = start_slice(slice_id)
        start_data = start_response.get_json()
        
        return jsonify({
            'message': 'Slice restart completed',
            'slice_id': slice_id,
            'restart_result': {
                'stop': stop_data,
                'start': start_data
            }
        })
        
    except Exception as e:
        logger.error(f"Critical error restarting slice {slice_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

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
    """Crea un nuevo slice con soporte R5"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Validar datos (usa la función actualizada)
        is_valid, error = validate_slice_data(data)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        slice_id = str(uuid.uuid4())
        db = get_db()
        
        # Calcular recursos totales (sin cambios)
        total_vcpus = total_ram = total_disk = 0
        for node in data['nodes']:
            flavor = VM_FLAVORS[node['flavor']]
            total_vcpus += flavor['vcpus']
            total_ram += flavor['ram']
            total_disk += flavor['disk']
        
        try:
            # Insertar slice (sin cambios)
            db.execute('''
                INSERT INTO slices (id, user_id, name, description, template_id, 
                                  infrastructure, availability_zone, placement_policy,
                                  total_vcpus, total_ram, total_disk)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                slice_id, g.current_user['user_id'], data['name'],
                data.get('description'), data.get('template_id'),
                data['infrastructure'], data.get('availability_zone'),
                data.get('placement_policy', 'balanced'),
                total_vcpus, total_ram, total_disk
            ))
            
            # Insertar nodos CON NUEVOS CAMPOS
            for node in data['nodes']:
                db.execute('''
                    INSERT INTO nodes (id, slice_id, name, image, flavor, 
                                     management_ip, internet_access)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), slice_id, node['name'],
                    node['image'], node['flavor'],
                    node.get('management_ip'),           # ← NUEVO
                    node.get('internet_access', False)   # ← NUEVO
                ))
            
            # Insertar redes CON NUEVOS CAMPOS
            for network in data['networks']:
                db.execute('''
                    INSERT INTO slice_networks (id, slice_id, name, cidr, vlan_id, 
                                               gateway, dns_servers, network_type, 
                                               internet_access, is_management)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()), slice_id, network['name'],
                    network['cidr'], network.get('vlan_id'),
                    network.get('gateway'), 
                    json.dumps(network.get('dns_servers', [])),
                    network.get('network_type', 'data'),        # ← NUEVO
                    network.get('internet_access', False),      # ← NUEVO
                    network.get('network_type') == 'management' # ← NUEVO
                ))
            
            # Insertar conexiones (sin cambios)
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
                            str(uuid.uuid4()), slice_id,
                            source_node['id'], target_node['id'], network['id']
                        ))
            
            db.commit()
            logger.info(f"Slice created with R5 support: {slice_id}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error creating slice: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        return jsonify({
            'id': slice_id,
            'message': 'Slice created successfully with R5 support',
            'status': 'draft',
            'resources': {
                'total_vcpus': total_vcpus,
                'total_ram': total_ram,
                'total_disk': total_disk
            },
            'r5_features': {
                'management_networks': len([n for n in data['networks'] if n.get('network_type') == 'management']),
                'internet_enabled_nodes': len([n for n in data['nodes'] if n.get('internet_access')]),
                'trunk_networks': len([n for n in data['networks'] if n.get('network_type') == 'trunk'])
            }
        }), 201
        
    except Exception as e:
        logger.error(f"Create slice error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/slices/<slice_id>', methods=['GET'])
@token_required
def get_slice(slice_id):
    """Obtiene detalles de un slice con campos R5"""
    try:
        db = get_db()
        
        # Verificar propiedad (sin cambios)
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND deleted_at IS NULL
        ''', (slice_id,)).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found'}), 404
        
        # Verificar permisos (sin cambios)
        if (slice_data['user_id'] != g.current_user['user_id'] and 
            'view_all_slices' not in g.current_user.get('permissions', [])):
            return jsonify({'error': 'Access denied'}), 403
        
        # Obtener nodos CON NUEVOS CAMPOS
        nodes = db.execute('''
            SELECT * FROM nodes WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        # Obtener redes CON NUEVOS CAMPOS
        networks = db.execute('''
            SELECT * FROM slice_networks WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        # Obtener conexiones (sin cambios)
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
        
        # Agregar estadísticas R5
        result['r5_summary'] = {
            'management_networks': len([n for n in networks if n['network_type'] == 'management']),
            'trunk_networks': len([n for n in networks if n['network_type'] == 'trunk']),
            'internet_enabled_nodes': len([n for n in nodes if n['internet_access']]),
            'total_networks_by_type': {}
        }
        
        # Contar redes por tipo
        for network in networks:
            net_type = network['network_type']
            if net_type not in result['r5_summary']['total_networks_by_type']:
                result['r5_summary']['total_networks_by_type'][net_type] = 0
            result['r5_summary']['total_networks_by_type'][net_type] += 1
        
        # Parsear datos de despliegue si existen (sin cambios)
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
    """Despliega un slice usando el driver correspondiente"""
    try:
        db = get_db()
        
        # Verificar propiedad del slice
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()
        
        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404
        
        # Convertir slice_data a dict
        slice_dict = dict(slice_data)
        
        if slice_dict['status'] not in ['draft', 'error']:
            return jsonify({'error': f'Cannot deploy slice in status: {slice_dict["status"]}'}), 400
        
        # Actualizar estado a 'validating'
        db.execute('''
            UPDATE slices SET status = 'validating', updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (slice_id,))
        db.commit()
        
        # Obtener nodos y redes del slice
        nodes = db.execute('''
            SELECT * FROM nodes WHERE slice_id = ? ORDER BY name
        ''', (slice_id,)).fetchall()
        
        networks = db.execute('''
            SELECT * FROM slice_networks WHERE slice_id = ? ORDER BY name
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
        node_list = [dict(node) for node in nodes]  # Convertir a dict aquí también
        
        # Mapear flavors a recursos
        for node in node_list:
            flavor_name = node.get('flavor', 'small')
            if flavor_name in VM_FLAVORS:
                flavor = VM_FLAVORS[flavor_name]
                node['cpu'] = flavor['vcpus']
                node['ram'] = flavor['ram']
                node['disk'] = flavor['disk']
            else:
                # Valores por defecto si el flavor no existe
                node['cpu'] = 1
                node['ram'] = 1024
                node['disk'] = 10
        
        logger.info(f"Node list for placement: {node_list}")
        
        placement_result = placement_engine.calculate_placement(
            node_list,
            slice_dict['infrastructure'],
            slice_dict['availability_zone'],
            slice_dict['placement_policy']
        )
        
        if not placement_result['success']:
            logger.error(f"Placement failed: {placement_result.get('error')}")
        else:
            logger.info(f"Placement result: {placement_result}")

        if not placement_result['success']:
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ?
                WHERE id = ?
            ''', (placement_result['error'], slice_id))
            db.commit()
            return jsonify({'error': placement_result['error']}), 400
        
        # Obtener driver según infraestructura CON TOKEN DE AUTENTICACIÓN
        try:
            # Extraer token del header Authorization
            auth_header = request.headers.get('Authorization')
            token = None
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            
            # Obtener driver con token para Network Service
            from .orchestrator import Orchestrator
            orchestrator = Orchestrator()
            driver = orchestrator.select_driver(slice_dict['infrastructure'], token=token)
                
        except ValueError as e:
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ?
                WHERE id = ?
            ''', (str(e), slice_id))
            db.commit()
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error initializing driver: {e}")
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ?
                WHERE id = ?
            ''', (f"Driver initialization failed: {str(e)}", slice_id))
            db.commit()
            return jsonify({'error': 'Driver initialization failed'}), 500
        
        # Convertir networks a lista de diccionarios
        networks_list = [dict(net) for net in networks]
        
        # Preparar configuración para el driver
        slice_config = {
            'id': slice_id,
            'name': slice_dict['name'],
            'infrastructure': slice_dict['infrastructure'],
            'nodes': [
                {
                    'name': node['name'],
                    'image': node['image'],
                    'flavor': node['flavor'],
                    'cpu': node.get('cpu', 1),
                    'ram': node.get('ram', 1024),
                    'disk': node.get('disk', 10),
                    'internet_access': bool(node.get('internet_access', False)),
                    'management_ip': node.get('management_ip')
                }
                for node in node_list
            ],
            'networks': [
                {
                    'name': net['name'],
                    'cidr': net['cidr'],
                    'gateway': net['gateway'],
                    'dns_servers': json.loads(net['dns_servers']) if net['dns_servers'] else [],
                    'network_type': net.get('network_type', 'data'),
                    'internet_access': bool(net.get('internet_access', False)),
                    'is_management': bool(net.get('is_management', False))
                }
                for net in networks_list
            ]
        }
                
        # Actualizar estado a 'deploying'
        db.execute('''
            UPDATE slices SET status = 'deploying', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (slice_id,))
        db.commit()
        
        # Ejecutar deployment usando el driver
        logger.info(f"Starting deployment of slice {slice_id} using {driver.driver_name}")
        
        deployment_result = driver.deploy_slice(slice_config, placement_result['placement'])
        
        logger.info(f"Deployment result status: {deployment_result.get('status')}")
        
        # Actualizar base de datos con resultados
        if deployment_result['status'] == 'success':
            # Actualizar nodos con información de deployment
            for vm_info in deployment_result['deployed_vms']:
                db.execute('''
                    UPDATE nodes 
                    SET vm_id = ?, ip_address = ?, console_url = ?, status = 'running', assigned_host = ?
                    WHERE slice_id = ? AND name = ?
                ''', (
                    vm_info['vm_id'], 
                    vm_info.get('ip_address'), 
                    vm_info.get('console_url'),
                    vm_info.get('server'),  # assigned_host
                    slice_id, 
                    vm_info['name']
                ))
            
            # Actualizar redes si se crearon
            for network_info in deployment_result.get('created_networks', []):
                db.execute('''
                    UPDATE slice_networks 
                    SET vlan_id = ?, status = 'active'
                    WHERE slice_id = ? AND name = ?
                ''', (
                    network_info.get('vlan_id'),
                    slice_id,
                    network_info['name']
                ))
            
            # Actualizar slice
            db.execute('''
                UPDATE slices 
                SET status = 'active', 
                    deployment_data = ?,
                    deployed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = NULL
                WHERE id = ?
            ''', (json.dumps(deployment_result), slice_id))
            
            db.commit()
            
            logger.info(f"✓ Slice {slice_id} deployed successfully")
            
            return jsonify({
                'status': 'success',
                'slice_id': slice_id,
                'deployment_result': deployment_result,
                'message': 'Slice deployed successfully'
            })
            
        elif deployment_result['status'] == 'partial':
            # Deployment parcial - algunas cosas funcionaron
            error_message = f"Partial deployment: {'; '.join(deployment_result.get('errors', []))}"
            
            # Actualizar nodos que sí se desplegaron
            for vm_info in deployment_result.get('deployed_vms', []):
                db.execute('''
                    UPDATE nodes 
                    SET vm_id = ?, ip_address = ?, console_url = ?, status = 'running', assigned_host = ?
                    WHERE slice_id = ? AND name = ?
                ''', (
                    vm_info['vm_id'], 
                    vm_info.get('ip_address'), 
                    vm_info.get('console_url'),
                    vm_info.get('server'),
                    slice_id, 
                    vm_info['name']
                ))
            
            # Actualizar slice como activo pero con advertencias
            db.execute('''
                UPDATE slices 
                SET status = 'active', 
                    deployment_data = ?,
                    deployed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = ?
                WHERE id = ?
            ''', (json.dumps(deployment_result), error_message, slice_id))
            
            db.commit()
            
            logger.warning(f"⚠️ Slice {slice_id} deployed with warnings: {error_message}")
            
            return jsonify({
                'status': 'partial',
                'slice_id': slice_id,
                'deployment_result': deployment_result,
                'message': 'Slice deployed with warnings',
                'warnings': deployment_result.get('errors', [])
            })
            
        else:
            # Error en deployment
            error_message = deployment_result.get('error', 'Deployment failed')
            
            db.execute('''
                UPDATE slices 
                SET status = 'error', 
                    error_message = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (error_message, slice_id))
            db.commit()
            
            logger.error(f"✗ Slice {slice_id} deployment failed: {error_message}")
            
            return jsonify({
                'status': 'failed',
                'slice_id': slice_id,
                'error': error_message,
                'deployment_result': deployment_result
            }), 500
        
    except Exception as e:
        logger.error(f"Critical error deploying slice {slice_id}: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Actualizar estado a error
        try:
            db = get_db()
            db.execute('''
                UPDATE slices SET status = 'error', error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (str(e), slice_id))
            db.commit()
        except:
            pass
        
        return jsonify({'error': 'Internal server error'}), 500


# Agregar endpoint para eliminar slice
@app.route('/slices/<slice_id>', methods=['DELETE'])
@token_required
def delete_slice(slice_id):
    """Elimina un slice completamente"""
    try:
        db = get_db()

        # Verificar propiedad
        slice_data = db.execute('''
            SELECT * FROM slices WHERE id = ? AND user_id = ? AND deleted_at IS NULL
        ''', (slice_id, g.current_user['user_id'])).fetchone()

        if not slice_data:
            return jsonify({'error': 'Slice not found or access denied'}), 404

        # Si el slice está desplegado, usar driver para eliminarlo
        if slice_data['status'] in ['active', 'error']:
            try:
                driver = get_driver(slice_data['infrastructure'])

                # Cargar resultado de despliegue
                deployment_result = json.loads(slice_data['deployment_data']) if slice_data['deployment_data'] else {}
                vm_list = deployment_result.get('deployed_vms', [])

                logger.debug(f"VMs to destroy for slice {slice_id}: {json.dumps(vm_list, indent=2)}")

                # Llamar solo al método del driver, que ahora destruye cada VM
                destruction_result = driver.destroy_slice(slice_id, vm_list)

                logger.info(f"Slice {slice_id} destruction result: {destruction_result}")

            except Exception as e:
                logger.error(f"Error destroying slice infrastructure: {e}")

        # Marcar como eliminado en BD
        db.execute('''
            UPDATE slices 
            SET status = 'deleted', deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (slice_id,))

        db.commit()

        logger.info(f"✓ Slice {slice_id} deleted successfully")

        return jsonify({
            'message': 'Slice deleted successfully',
            'slice_id': slice_id
        })

    except Exception as e:
        logger.error(f"Error deleting slice {slice_id}: {e}")
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

@app.route('/status', methods=['GET'])
@token_required
def get_cluster_status_endpoint():
    """Endpoint para obtener estado del cluster"""
    try:
        status = get_cluster_status()
        
        # Agregar información de base de datos
        db = get_db()
        db_servers = db.execute('''
            SELECT hostname, infrastructure, total_vcpus, total_ram, total_disk, 
                   used_vcpus, used_ram, used_disk, last_updated
            FROM server_resources 
            WHERE infrastructure = 'linux'
            ORDER BY hostname
        ''').fetchall()
        
        status['database_servers'] = [dict(server) for server in db_servers]
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting cluster status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/sync', methods=['POST'])
@token_required
def sync_cluster_config():
    """Sincroniza configuración del cluster con la base de datos"""
    try:
        # Verificar permisos de admin
        if 'manage_cluster' not in g.current_user.get('permissions', []):
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        db = get_db()
        
        # Actualizar servidores con configuración real
        update_real_server_resources(db)
        
        # Obtener estado actualizado
        status = get_cluster_status()
        
        return jsonify({
            'message': 'Cluster configuration synchronized successfully',
            'status': status
        })
        
    except Exception as e:
        logger.error(f"Error syncing cluster config: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5002, debug=False)
