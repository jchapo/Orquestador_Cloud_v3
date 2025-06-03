#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Network Service (Mejorado)
Maneja redes, VLANs y seguridad con OpenFlow Controller (R5)
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
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'network_service.db')
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025')
app.config['OPENFLOW_CONTROLLER_URL'] = os.getenv('OPENFLOW_CONTROLLER_URL', 'http://localhost:6633')
app.config['OVS_MANAGER_URL'] = os.getenv('OVS_MANAGER_URL', 'http://localhost:6634')

# Rangos VLAN por infraestructura
VLAN_RANGES = {
    'linux': {'start': 100, 'end': 199},
    'openstack': {'start': 200, 'end': 299}
}

# Subredes asignadas por grupo (del documento del proyecto)
GROUP_SUBNETS = {
    'linux': {
        1: '10.60.1.0/24', 2: '10.60.3.0/24', 3: '10.60.5.0/24',
        4: '10.60.7.0/24', 5: '10.60.9.0/24', 6: '10.60.11.0/24'
    },
    'openstack': {
        1: '10.60.2.0/24', 2: '10.60.4.0/24', 3: '10.60.6.0/24',
        4: '10.60.8.0/24', 5: '10.60.10.0/24', 6: '10.60.12.0/24'
    }
}

def get_db():
    """Obtiene conexión a la base de datos"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos con esquema mejorado"""
    with app.app_context():
        db = get_db()
        
        # Tabla principal de redes
        db.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                slice_id TEXT,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL,
                vlan_id INTEGER UNIQUE,
                infrastructure TEXT NOT NULL CHECK (infrastructure IN ('linux', 'openstack')),
                gateway TEXT,
                dns_servers TEXT,
                is_external BOOLEAN DEFAULT 0,
                is_provider BOOLEAN DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                ovs_bridge TEXT,
                openflow_rules TEXT,
                security_groups TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla de reglas de seguridad
        db.execute('''
            CREATE TABLE IF NOT EXISTS security_rules (
                id TEXT PRIMARY KEY,
                network_id TEXT NOT NULL,
                rule_type TEXT NOT NULL CHECK (rule_type IN ('ingress', 'egress')),
                protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp', 'icmp', 'any')),
                port_range_min INTEGER,
                port_range_max INTEGER,
                source_cidr TEXT,
                destination_cidr TEXT,
                action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
                priority INTEGER DEFAULT 100,
                description TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (network_id) REFERENCES networks (id) ON DELETE CASCADE
            )
        ''')
        
        # Tabla de asignaciones de VLAN
        db.execute('''
            CREATE TABLE IF NOT EXISTS vlan_assignments (
                vlan_id INTEGER PRIMARY KEY,
                infrastructure TEXT NOT NULL,
                network_id TEXT,
                is_reserved BOOLEAN DEFAULT 0,
                assigned_at TIMESTAMP,
                FOREIGN KEY (network_id) REFERENCES networks (id)
            )
        ''')
        
        # Tabla de switches OVS
        db.execute('''
            CREATE TABLE IF NOT EXISTS ovs_switches (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                infrastructure TEXT NOT NULL,
                management_ip TEXT NOT NULL,
                datapath_id TEXT,
                status TEXT DEFAULT 'active',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabla de puertos en switches
        db.execute('''
            CREATE TABLE IF NOT EXISTS ovs_ports (
                id TEXT PRIMARY KEY,
                switch_id TEXT NOT NULL,
                port_name TEXT NOT NULL,
                port_number INTEGER,
                vlan_tag INTEGER,
                port_type TEXT DEFAULT 'access',
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (switch_id) REFERENCES ovs_switches (id)
            )
        ''')
        
        # Tabla de flujos OpenFlow
        db.execute('''
            CREATE TABLE IF NOT EXISTS openflow_flows (
                id TEXT PRIMARY KEY,
                switch_id TEXT NOT NULL,
                network_id TEXT,
                table_id INTEGER DEFAULT 0,
                priority INTEGER DEFAULT 100,
                match_fields TEXT NOT NULL,
                actions TEXT NOT NULL,
                cookie TEXT,
                flow_id_controller TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (switch_id) REFERENCES ovs_switches (id),
                FOREIGN KEY (network_id) REFERENCES networks (id)
            )
        ''')
        
        db.commit()
        
        # Crear datos por defecto
        create_default_vlans(db)
        create_default_switches(db)

def create_default_vlans(db):
    """Crea rangos de VLAN por defecto"""
    for infrastructure, vlan_range in VLAN_RANGES.items():
        for vlan_id in range(vlan_range['start'], vlan_range['end'] + 1):
            existing = db.execute(
                'SELECT vlan_id FROM vlan_assignments WHERE vlan_id = ?', 
                (vlan_id,)
            ).fetchone()
            
            if not existing:
                db.execute('''
                    INSERT INTO vlan_assignments (vlan_id, infrastructure, is_reserved)
                    VALUES (?, ?, ?)
                ''', (vlan_id, infrastructure, False))
    
    db.commit()

def create_default_switches(db):
    """Crea switches OVS por defecto"""
    default_switches = [
        ('ovs1', 'linux', '192.168.201.5'),
        ('ovs2', 'openstack', '192.168.202.5')
    ]
    
    for name, infra, mgmt_ip in default_switches:
        existing = db.execute(
            'SELECT id FROM ovs_switches WHERE name = ?', (name,)
        ).fetchone()
        
        if not existing:
            db.execute('''
                INSERT INTO ovs_switches (id, name, infrastructure, management_ip)
                VALUES (?, ?, ?, ?)
            ''', (str(uuid.uuid4()), name, infra, mgmt_ip))
    
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

def validate_cidr(cidr_str):
    """Valida formato CIDR"""
    try:
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        return True, network
    except ValueError as e:
        return False, str(e)

def get_next_available_vlan(infrastructure: str, db) -> Optional[int]:
    """Obtiene siguiente VLAN disponible"""
    available = db.execute('''
        SELECT vlan_id FROM vlan_assignments 
        WHERE infrastructure = ? AND network_id IS NULL AND is_reserved = 0
        ORDER BY vlan_id
        LIMIT 1
    ''', (infrastructure,)).fetchone()
    
    return available['vlan_id'] if available else None

def allocate_vlan(vlan_id: int, network_id: str, db):
    """Asigna VLAN a una red"""
    db.execute('''
        UPDATE vlan_assignments 
        SET network_id = ?, assigned_at = CURRENT_TIMESTAMP
        WHERE vlan_id = ?
    ''', (network_id, vlan_id))

def release_vlan(network_id: str, db):
    """Libera VLAN de una red"""
    db.execute('''
        UPDATE vlan_assignments 
        SET network_id = NULL, assigned_at = NULL
        WHERE network_id = ?
    ''', (network_id,))

class OpenFlowController:
    """Cliente para interactuar con controlador OpenFlow"""
    
    def __init__(self, controller_url):
        self.controller_url = controller_url
    
    def create_network_flows(self, switch_id: str, vlan_id: int, network_cidr: str) -> bool:
        """Crea flujos OpenFlow para una red"""
        try:
            flows = [
                # Flujo para permitir tráfico dentro de la VLAN
                {
                    'table_id': 0,
                    'priority': 200,
                    'match': {
                        'dl_vlan': vlan_id,
                        'dl_type': 0x0800  # IPv4
                    },
                    'actions': [
                        {'type': 'output', 'port': 'flood'}
                    ]
                },
                # Flujo para ARP dentro de la VLAN
                {
                    'table_id': 0,
                    'priority': 300,
                    'match': {
                        'dl_vlan': vlan_id,
                        'dl_type': 0x0806  # ARP
                    },
                    'actions': [
                        {'type': 'output', 'port': 'flood'}
                    ]
                },
                # Flujo por defecto para drop
                {
                    'table_id': 0,
                    'priority': 1,
                    'match': {
                        'dl_vlan': vlan_id
                    },
                    'actions': [
                        {'type': 'drop'}
                    ]
                }
            ]
            
            # Enviar flujos al controlador
            for flow in flows:
                response = requests.post(
                    f"{self.controller_url}/flows/{switch_id}",
                    json=flow,
                    timeout=10
                )
                if response.status_code not in [200, 201]:
                    logger.error(f"Failed to create flow: {response.text}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"OpenFlow controller error: {e}")
            return False
    
    def delete_network_flows(self, switch_id: str, vlan_id: int) -> bool:
        """Elimina flujos OpenFlow de una red"""
        try:
            response = requests.delete(
                f"{self.controller_url}/flows/{switch_id}",
                params={'vlan_id': vlan_id},
                timeout=10
            )
            return response.status_code in [200, 204]
            
        except Exception as e:
            logger.error(f"OpenFlow controller error: {e}")
            return False
    
    def apply_security_rules(self, switch_id: str, vlan_id: int, rules: List[Dict]) -> bool:
        """Aplica reglas de seguridad como flujos OpenFlow"""
        try:
            for rule in rules:
                flow = {
                    'table_id': 1,  # Tabla de seguridad
                    'priority': rule.get('priority', 100),
                    'match': self._build_match_from_rule(rule, vlan_id),
                    'actions': [
                        {'type': 'output', 'port': 'normal'} if rule['action'] == 'allow' 
                        else {'type': 'drop'}
                    ]
                }
                
                response = requests.post(
                    f"{self.controller_url}/flows/{switch_id}",
                    json=flow,
                    timeout=10
                )
                
                if response.status_code not in [200, 201]:
                    logger.error(f"Failed to apply security rule: {response.text}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Security rules error: {e}")
            return False
    
    def _build_match_from_rule(self, rule: Dict, vlan_id: int) -> Dict:
        """Construye match OpenFlow desde regla de seguridad"""
        match = {'dl_vlan': vlan_id}
        
        if rule['protocol'] == 'tcp':
            match['nw_proto'] = 6
        elif rule['protocol'] == 'udp':
            match['nw_proto'] = 17
        elif rule['protocol'] == 'icmp':
            match['nw_proto'] = 1
        
        if rule.get('port_range_min'):
            if rule['rule_type'] == 'ingress':
                match['tp_dst'] = rule['port_range_min']
            else:
                match['tp_src'] = rule['port_range_min']
        
        if rule.get('source_cidr'):
            match['nw_src'] = rule['source_cidr']
        
        if rule.get('destination_cidr'):
            match['nw_dst'] = rule['destination_cidr']
        
        return match

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'network',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/api/networks', methods=['GET'])
@token_required
def list_networks():
    """Lista redes del usuario"""
    try:
        db = get_db()
        infrastructure = request.args.get('infrastructure')
        slice_id = request.args.get('slice_id')
        
        query = '''
            SELECT n.*, va.vlan_id
            FROM networks n
            LEFT JOIN vlan_assignments va ON n.id = va.network_id
            WHERE n.user_id = ?
        '''
        params = [g.current_user['user_id']]
        
        if infrastructure:
            query += ' AND n.infrastructure = ?'
            params.append(infrastructure)
        
        if slice_id:
            query += ' AND n.slice_id = ?'
            params.append(slice_id)
        
        query += ' ORDER BY n.created_at DESC'
        
        networks = db.execute(query, params).fetchall()
        
        result = []
        for network in networks:
            net_dict = dict(network)
            
            # Obtener reglas de seguridad
            security_rules = db.execute('''
                SELECT * FROM security_rules 
                WHERE network_id = ? AND is_active = 1
                ORDER BY priority DESC
            ''', (network['id'],)).fetchall()
            
            net_dict['security_rules'] = [dict(rule) for rule in security_rules]
            
            # Parsear campos JSON
            if net_dict['dns_servers']:
                try:
                    net_dict['dns_servers'] = json.loads(net_dict['dns_servers'])
                except:
                    net_dict['dns_servers'] = []
            
            result.append(net_dict)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List networks error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/networks', methods=['POST'])
@token_required
def create_network():
    """Crea una nueva red"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Validar campos requeridos
        required_fields = ['name', 'cidr', 'infrastructure']
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        # Validaciones
        if data['infrastructure'] not in ['linux', 'openstack']:
            return jsonify({'error': 'Infrastructure must be "linux" or "openstack"'}), 400
        
        is_valid_cidr, cidr_result = validate_cidr(data['cidr'])
        if not is_valid_cidr:
            return jsonify({'error': f'Invalid CIDR: {cidr_result}'}), 400
        
        network_id = str(uuid.uuid4())
        db = get_db()
        
        try:
            # Obtener VLAN automáticamente si no se especifica
            vlan_id = data.get('vlan_id')
            if not vlan_id:
                vlan_id = get_next_available_vlan(data['infrastructure'], db)
                if not vlan_id:
                    return jsonify({'error': f'No available VLANs for {data["infrastructure"]}'}), 400
            else:
                # Verificar que la VLAN esté disponible
                existing_vlan = db.execute('''
                    SELECT network_id FROM vlan_assignments 
                    WHERE vlan_id = ? AND infrastructure = ?
                ''', (vlan_id, data['infrastructure'])).fetchone()
                
                if existing_vlan and existing_vlan['network_id']:
                    return jsonify({'error': f'VLAN {vlan_id} already in use'}), 409
            
            # Calcular gateway si no se proporciona
            gateway = data.get('gateway')
            if not gateway:
                network = ipaddress.IPv4Network(data['cidr'], strict=False)
                gateway = str(list(network.hosts())[0])  # Primera IP disponible
            
            # Crear red
            db.execute('''
                INSERT INTO networks (
                    id, user_id, slice_id, name, cidr, infrastructure,
                    gateway, dns_servers, is_external, is_provider, ovs_bridge
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                network_id,
                g.current_user['user_id'],
                data.get('slice_id'),
                data['name'],
                data['cidr'],
                data['infrastructure'],
                gateway,
                json.dumps(data.get('dns_servers', ['8.8.8.8', '8.8.4.4'])),
                data.get('is_external', False),
                data.get('is_provider', False),
                f"br-{data['infrastructure']}"
            ))
            
            # Asignar VLAN
            allocate_vlan(vlan_id, network_id, db)
            
            # Crear reglas de seguridad por defecto
            default_rules = [
                {
                    'rule_type': 'ingress',
                    'protocol': 'any',
                    'source_cidr': data['cidr'],
                    'action': 'allow',
                    'priority': 200,
                    'description': 'Allow intra-network traffic'
                },
                {
                    'rule_type': 'egress',
                    'protocol': 'any',
                    'destination_cidr': '0.0.0.0/0',
                    'action': 'allow',
                    'priority': 100,
                    'description': 'Allow all outbound traffic'
                }
            ]
            
            if data.get('security_rules'):
                default_rules.extend(data['security_rules'])
            
            for rule in default_rules:
                db.execute('''
                    INSERT INTO security_rules (
                        id, network_id, rule_type, protocol,
                        port_range_min, port_range_max, source_cidr, destination_cidr,
                        action, priority, description
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(uuid.uuid4()),
                    network_id,
                    rule['rule_type'],
                    rule['protocol'],
                    rule.get('port_range_min'),
                    rule.get('port_range_max'),
                    rule.get('source_cidr'),
                    rule.get('destination_cidr'),
                    rule['action'],
                    rule['priority'],
                    rule.get('description', '')
                ))
            
            db.commit()
            
            # Configurar OpenFlow si es necesario
            if data.get('configure_openflow', True):
                try:
                    # Obtener switch para esta infraestructura
                    switch = db.execute('''
                        SELECT * FROM ovs_switches 
                        WHERE infrastructure = ? AND status = 'active'
                        LIMIT 1
                    ''', (data['infrastructure'],)).fetchone()
                    
                    if switch:
                        controller = OpenFlowController(app.config['OPENFLOW_CONTROLLER_URL'])
                        success = controller.create_network_flows(
                            switch['id'], vlan_id, data['cidr']
                        )
                        
                        if success:
                            # Aplicar reglas de seguridad
                            security_rules = db.execute('''
                                SELECT * FROM security_rules 
                                WHERE network_id = ? AND is_active = 1
                            ''', (network_id,)).fetchall()
                            
                            controller.apply_security_rules(
                                switch['id'], vlan_id, [dict(r) for r in security_rules]
                            )
                            
                            # Actualizar estado
                            db.execute('''
                                UPDATE networks SET status = 'active' WHERE id = ?
                            ''', (network_id,))
                            db.commit()
                        else:
                            logger.warning(f"Failed to configure OpenFlow for network {network_id}")
                
                except Exception as e:
                    logger.error(f"OpenFlow configuration error: {e}")
            
            logger.info(f"Network created: {network_id} with VLAN {vlan_id}")
            
            return jsonify({
                'id': network_id,
                'name': data['name'],
                'cidr': data['cidr'],
                'vlan_id': vlan_id,
                'gateway': gateway,
                'infrastructure': data['infrastructure'],
                'status': 'active',
                'message': 'Network created successfully'
            }), 201
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error creating network: {e}")
            return jsonify({'error': 'Database error'}), 500
        
    except Exception as e:
        logger.error(f"Create network error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/networks/<network_id>', methods=['DELETE'])
@token_required
def delete_network(network_id):
    """Elimina una red"""
    try:
        db = get_db()
        
        # Verificar propiedad
        network = db.execute('''
            SELECT * FROM networks WHERE id = ? AND user_id = ?
        ''', (network_id, g.current_user['user_id'])).fetchone()
        
        if not network:
            return jsonify({'error': 'Network not found or access denied'}), 404
        
        # Obtener VLAN
        vlan_assignment = db.execute('''
            SELECT vlan_id FROM vlan_assignments WHERE network_id = ?
        ''', (network_id,)).fetchone()
        
        try:
            # Eliminar flujos OpenFlow
            if vlan_assignment:
                switch = db.execute('''
                    SELECT * FROM ovs_switches 
                    WHERE infrastructure = ? AND status = 'active'
                    LIMIT 1
                ''', (network['infrastructure'],)).fetchone()
                
                if switch:
                    controller = OpenFlowController(app.config['OPENFLOW_CONTROLLER_URL'])
                    controller.delete_network_flows(switch['id'], vlan_assignment['vlan_id'])
            
            # Liberar VLAN
            release_vlan(network_id, db)
            
            # Eliminar reglas de seguridad
            db.execute('DELETE FROM security_rules WHERE network_id = ?', (network_id,))
            
            # Eliminar red
            db.execute('DELETE FROM networks WHERE id = ?', (network_id,))
            
            db.commit()
            
            logger.info(f"Network deleted: {network_id}")
            
            return jsonify({'message': 'Network deleted successfully'})
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error deleting network: {e}")
            return jsonify({'error': 'Database error'}), 500
        
    except Exception as e:
        logger.error(f"Delete network error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/networks/<network_id>/security-rules', methods=['POST'])
@token_required
def add_security_rule(network_id):
    """Añade regla de seguridad a una red"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        db = get_db()
        
        # Verificar propiedad de la red
        network = db.execute('''
            SELECT * FROM networks WHERE id = ? AND user_id = ?
        ''', (network_id, g.current_user['user_id'])).fetchone()
        
        if not network:
            return jsonify({'error': 'Network not found or access denied'}), 404
        
        # Validar regla
        required = ['rule_type', 'protocol', 'action']
        missing = [f for f in required if not data.get(f)]
        if missing:
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        if data['rule_type'] not in ['ingress', 'egress']:
            return jsonify({'error': 'rule_type must be "ingress" or "egress"'}), 400
        
        if data['protocol'] not in ['tcp', 'udp', 'icmp', 'any']:
            return jsonify({'error': 'Invalid protocol'}), 400
        
        if data['action'] not in ['allow', 'deny']:
            return jsonify({'error': 'action must be "allow" or "deny"'}), 400
        
        rule_id = str(uuid.uuid4())
        
        try:
            # Crear regla
            db.execute('''
                INSERT INTO security_rules (
                    id, network_id, rule_type, protocol,
                    port_range_min, port_range_max, source_cidr, destination_cidr,
                    action, priority, description
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_id,
                network_id,
                data['rule_type'],
                data['protocol'],
                data.get('port_range_min'),
                data.get('port_range_max'),
                data.get('source_cidr'),
                data.get('destination_cidr'),
                data['action'],
                data.get('priority', 100),
                data.get('description', '')
            ))
            
            db.commit()
            
            # Actualizar flujos OpenFlow
            vlan_assignment = db.execute('''
                SELECT vlan_id FROM vlan_assignments WHERE network_id = ?
            ''', (network_id,)).fetchone()
            
            if vlan_assignment:
                switch = db.execute('''
                    SELECT * FROM ovs_switches 
                    WHERE infrastructure = ? AND status = 'active'
                    LIMIT 1
                ''', (network['infrastructure'],)).fetchone()
                
                if switch:
                    controller = OpenFlowController(app.config['OPENFLOW_CONTROLLER_URL'])
                    controller.apply_security_rules(
                        switch['id'], vlan_assignment['vlan_id'], [data]
                    )
            
            return jsonify({
                'id': rule_id,
                'message': 'Security rule added successfully'
            }), 201
            
        except Exception as e:
            db.rollback()
            logger.error(f"Database error adding security rule: {e}")
            return jsonify({'error': 'Database error'}), 500
        
    except Exception as e:
        logger.error(f"Add security rule error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/vlans', methods=['GET'])
@token_required
def list_vlans():
    """Lista VLANs disponibles"""
    try:
        db = get_db()
        infrastructure = request.args.get('infrastructure')
        
        query = '''
            SELECT va.*, n.name as network_name, n.user_id as network_owner
            FROM vlan_assignments va
            LEFT JOIN networks n ON va.network_id = n.id
        '''
        params = []
        
        if infrastructure:
            query += ' WHERE va.infrastructure = ?'
            params.append(infrastructure)
        
        query += ' ORDER BY va.vlan_id'
        
        vlans = db.execute(query, params).fetchall()
        
        return jsonify([dict(vlan) for vlan in vlans])
        
    except Exception as e:
        logger.error(f"List VLANs error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/switches', methods=['GET'])
@token_required
def list_switches():
    """Lista switches OVS"""
    try:
        db = get_db()
        
        switches = db.execute('''
            SELECT * FROM ovs_switches ORDER BY infrastructure, name
        ''').fetchall()
        
        result = []
        for switch in switches:
            switch_dict = dict(switch)
            
            # Obtener puertos del switch
            ports = db.execute('''
                SELECT * FROM ovs_ports WHERE switch_id = ? ORDER BY port_number
            ''', (switch['id'],)).fetchall()
            
            switch_dict['ports'] = [dict(port) for port in ports]
            result.append(switch_dict)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"List switches error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5004, debug=False)
