# slice_service/models.py
from enum import Enum
from datetime import datetime
import uuid
from typing import List, Dict, Optional
from database import get_db

class SliceStatus(Enum):
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    DELETING = "deleting"

class VMStatus(Enum):
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DELETING = "deleting"

class TopologyType(Enum):
    LINEAR = "linear"
    MESH = "mesh"
    TREE = "tree"
    RING = "ring"
    BUS = "bus"
    CUSTOM = "custom"

class Slice:
    def __init__(self, id=None, user_id=None, name=None, description=None,
                 infrastructure=None, topology_type=None, status=None,
                 network_range=None, created_at=None, updated_at=None):
        self.id = id or str(uuid.uuid4())
        self.user_id = user_id
        self.name = name
        self.description = description
        self.infrastructure = infrastructure
        self.topology_type = topology_type
        self.status = status or SliceStatus.PENDING.value
        self.network_range = network_range
        self.created_at = created_at
        self.updated_at = updated_at

    def save(self):
        """Crear o actualizar slice en BD"""
        db = get_db()
        
        # Verificar si existe
        existing = db.execute(
            'SELECT id FROM slices WHERE id = ?', (self.id,)
        ).fetchone()
        
        if existing:
            # Actualizar
            db.execute('''
                UPDATE slices SET 
                    name = ?, description = ?, status = ?, 
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (self.name, self.description, self.status, self.id))
        else:
            # Crear nuevo
            db.execute('''
                INSERT INTO slices (
                    id, user_id, name, description, infrastructure,
                    topology_type, status, network_range
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.id, self.user_id, self.name, self.description,
                self.infrastructure, self.topology_type, self.status,
                self.network_range
            ))
        
        db.commit()
        return self

    @classmethod
    def get_by_id(cls, slice_id: str) -> Optional['Slice']:
        """Obtener slice por ID"""
        db = get_db()
        row = db.execute(
            'SELECT * FROM slices WHERE id = ?', (slice_id,)
        ).fetchone()
        
        if row:
            return cls(**dict(row))
        return None

    @classmethod
    def get_by_user(cls, user_id: str) -> List['Slice']:
        """Obtener todos los slices de un usuario"""
        db = get_db()
        rows = db.execute(
            'SELECT * FROM slices WHERE user_id = ? ORDER BY created_at DESC',
            (user_id,)
        ).fetchall()
        
        return [cls(**dict(row)) for row in rows]

    def delete(self):
        """Eliminar slice y todos sus componentes"""
        db = get_db()
        
        # Eliminar en orden: networks -> vms -> slice
        db.execute('DELETE FROM slice_networks WHERE slice_id = ?', (self.id,))
        db.execute('DELETE FROM slice_vms WHERE slice_id = ?', (self.id,))
        db.execute('DELETE FROM slices WHERE id = ?', (self.id,))
        
        db.commit()

    def to_dict(self) -> Dict:
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'infrastructure': self.infrastructure,
            'topology_type': self.topology_type,
            'status': self.status,
            'network_range': self.network_range,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'vms': [vm.to_dict() for vm in self.get_vms()],
            'networks': [net.to_dict() for net in self.get_networks()]
        }

    def get_vms(self) -> List['SliceVM']:
        """Obtener todas las VMs del slice"""
        return SliceVM.get_by_slice(self.id)

    def get_networks(self) -> List['SliceNetwork']:
        """Obtener todas las redes del slice"""
        return SliceNetwork.get_by_slice(self.id)

class SliceVM:
    def __init__(self, id=None, slice_id=None, name=None, cpu=None, ram=None,
                 disk=None, image_id=None, status=None, external_id=None,
                 ip_address=None, created_at=None):
        self.id = id or str(uuid.uuid4())
        self.slice_id = slice_id
        self.name = name
        self.cpu = cpu
        self.ram = ram
        self.disk = disk
        self.image_id = image_id
        self.status = status or VMStatus.PENDING.value
        self.external_id = external_id
        self.ip_address = ip_address
        self.created_at = created_at

    def save(self):
        """Crear o actualizar VM en BD"""
        db = get_db()
        
        existing = db.execute(
            'SELECT id FROM slice_vms WHERE id = ?', (self.id,)
        ).fetchone()
        
        if existing:
            db.execute('''
                UPDATE slice_vms SET 
                    status = ?, external_id = ?, ip_address = ?
                WHERE id = ?
            ''', (self.status, self.external_id, self.ip_address, self.id))
        else:
            db.execute('''
                INSERT INTO slice_vms (
                    id, slice_id, name, cpu, ram, disk,
                    image_id, status, external_id, ip_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.id, self.slice_id, self.name, self.cpu, self.ram,
                self.disk, self.image_id, self.status, self.external_id,
                self.ip_address
            ))
        
        db.commit()
        return self

    @classmethod
    def get_by_slice(cls, slice_id: str) -> List['SliceVM']:
        """Obtener todas las VMs de un slice"""
        db = get_db()
        rows = db.execute(
            'SELECT * FROM slice_vms WHERE slice_id = ? ORDER BY created_at',
            (slice_id,)
        ).fetchall()
        
        return [cls(**dict(row)) for row in rows]

    @classmethod
    def get_by_id(cls, vm_id: str) -> Optional['SliceVM']:
        """Obtener VM por ID"""
        db = get_db()
        row = db.execute(
            'SELECT * FROM slice_vms WHERE id = ?', (vm_id,)
        ).fetchone()
        
        if row:
            return cls(**dict(row))
        return None

    def delete(self):
        """Eliminar VM"""
        db = get_db()
        db.execute('DELETE FROM slice_vms WHERE id = ?', (self.id,))
        db.commit()

    def to_dict(self) -> Dict:
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'slice_id': self.slice_id,
            'name': self.name,
            'cpu': self.cpu,
            'ram': self.ram,
            'disk': self.disk,
            'image_id': self.image_id,
            'status': self.status,
            'external_id': self.external_id,
            'ip_address': self.ip_address,
            'created_at': self.created_at
        }

class SliceNetwork:
    def __init__(self, id=None, slice_id=None, vm_from=None, vm_to=None,
                 network_type=None):
        self.id = id or str(uuid.uuid4())
        self.slice_id = slice_id
        self.vm_from = vm_from
        self.vm_to = vm_to
        self.network_type = network_type or "ethernet"

    def save(self):
        """Crear conexión de red en BD"""
        db = get_db()
        db.execute('''
            INSERT OR REPLACE INTO slice_networks (
                id, slice_id, vm_from, vm_to, network_type
            ) VALUES (?, ?, ?, ?, ?)
        ''', (self.id, self.slice_id, self.vm_from, self.vm_to, self.network_type))
        
        db.commit()
        return self

    @classmethod
    def get_by_slice(cls, slice_id: str) -> List['SliceNetwork']:
        """Obtener todas las conexiones de red de un slice"""
        db = get_db()
        rows = db.execute(
            'SELECT * FROM slice_networks WHERE slice_id = ?',
            (slice_id,)
        ).fetchall()
        
        return [cls(**dict(row)) for row in rows]

    def delete(self):
        """Eliminar conexión de red"""
        db = get_db()
        db.execute('DELETE FROM slice_networks WHERE id = ?', (self.id,))
        db.commit()

    def to_dict(self) -> Dict:
        """Convertir a diccionario para JSON"""
        return {
            'id': self.id,
            'slice_id': self.slice_id,
            'vm_from': self.vm_from,
            'vm_to': self.vm_to,
            'network_type': self.network_type
        }