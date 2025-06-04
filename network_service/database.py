# slice_service/database.py
import sqlite3
import os
from flask import g

DATABASE_PATH = 'slice_service.db'

def get_db():
    """Obtener conexión a la base de datos"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db():
    """Cerrar conexión a la base de datos"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Inicializar base de datos con esquemas"""
    db = sqlite3.connect(DATABASE_PATH)
    
    # Crear tabla de slices
    db.execute('''
        CREATE TABLE IF NOT EXISTS slices (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            infrastructure TEXT NOT NULL CHECK (infrastructure IN ('linux', 'openstack')),
            topology_type TEXT NOT NULL CHECK (topology_type IN ('linear', 'mesh', 'tree', 'ring', 'bus', 'custom')),
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'creating', 'running', 'stopping', 'stopped', 'error', 'deleting')),
            network_range TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear índices para slices
    db.execute('CREATE INDEX IF NOT EXISTS idx_slices_user_id ON slices(user_id)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_slices_status ON slices(status)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_slices_infrastructure ON slices(infrastructure)')
    
    # Crear tabla de VMs
    db.execute('''
        CREATE TABLE IF NOT EXISTS slice_vms (
            id TEXT PRIMARY KEY,
            slice_id TEXT NOT NULL,
            name TEXT NOT NULL,
            cpu INTEGER NOT NULL CHECK (cpu > 0),
            ram INTEGER NOT NULL CHECK (ram > 0),
            disk INTEGER NOT NULL CHECK (disk > 0),
            image_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'creating', 'running', 'stopped', 'error', 'deleting')),
            external_id TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (slice_id) REFERENCES slices(id) ON DELETE CASCADE
        )
    ''')
    
    # Crear índices para VMs
    db.execute('CREATE INDEX IF NOT EXISTS idx_slice_vms_slice_id ON slice_vms(slice_id)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_slice_vms_status ON slice_vms(status)')
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_slice_vms_name_slice ON slice_vms(slice_id, name)')
    
    # Crear tabla de redes
    db.execute('''
        CREATE TABLE IF NOT EXISTS slice_networks (
            id TEXT PRIMARY KEY,
            slice_id TEXT NOT NULL,
            vm_from TEXT NOT NULL,
            vm_to TEXT NOT NULL,
            network_type TEXT DEFAULT 'ethernet',
            FOREIGN KEY (slice_id) REFERENCES slices(id) ON DELETE CASCADE,
            FOREIGN KEY (vm_from) REFERENCES slice_vms(id) ON DELETE CASCADE,
            FOREIGN KEY (vm_to) REFERENCES slice_vms(id) ON DELETE CASCADE
        )
    ''')
    
    # Crear índices para redes
    db.execute('CREATE INDEX IF NOT EXISTS idx_slice_networks_slice_id ON slice_networks(slice_id)')
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_slice_networks_unique ON slice_networks(slice_id, vm_from, vm_to)')
    
    # Crear tabla de recursos (para tracking de uso)
    db.execute('''
        CREATE TABLE IF NOT EXISTS resource_usage (
            id TEXT PRIMARY KEY,
            infrastructure TEXT NOT NULL,
            server_name TEXT NOT NULL,
            cpu_used INTEGER DEFAULT 0,
            ram_used INTEGER DEFAULT 0,
            disk_used INTEGER DEFAULT 0,
            cpu_total INTEGER NOT NULL,
            ram_total INTEGER NOT NULL,
            disk_total INTEGER NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(infrastructure, server_name)
        )
    ''')
    
    db.execute('CREATE INDEX IF NOT EXISTS idx_resource_usage_infrastructure ON resource_usage(infrastructure)')
    
    db.commit()
    db.close()
    print("Database initialized successfully")

    # Tabla de pool de VLANs (NUEVA)
    db.execute('''
        CREATE TABLE IF NOT EXISTS vlan_pool (
            vlan_id INTEGER NOT NULL,
            infrastructure TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'allocated', 'reserved', 'error')),
            network_id TEXT,
            slice_id TEXT,
            usage_description TEXT,
            assigned_at TIMESTAMP,
            released_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (vlan_id, infrastructure)
        )
    ''')
    
    # Índices para optimización
    db.execute('CREATE INDEX IF NOT EXISTS idx_vlan_pool_state ON vlan_pool(infrastructure, state)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_vlan_pool_network ON vlan_pool(network_id)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_vlan_pool_slice ON vlan_pool(slice_id)')



def query_db(query, args=(), one=False):
    """Helper para ejecutar consultas"""
    db = get_db()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

if __name__ == "__main__":
    init_db()
