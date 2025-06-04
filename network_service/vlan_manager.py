# network_service/vlan_manager.py
import sqlite3
import logging
import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple
import threading

logger = logging.getLogger(__name__)

class VLANState(Enum):
    AVAILABLE = "available"
    ALLOCATED = "allocated"
    RESERVED = "reserved"
    ERROR = "error"

class VLANManager:
    """
    Gestor inteligente de VLANs con pooling y reutilización
    """
    
    def __init__(self, db_connection):
        self.db = db_connection
        self.lock = threading.Lock()  # Para operaciones thread-safe
        
        # Configuración de pools por infraestructura
        self.vlan_pools = {
            'linux': {
                'start': 100,
                'end': 199,
                'description': 'Linux Cluster VLAN Pool'
            },
            'openstack': {
                'start': 200,
                'end': 299,
                'description': 'OpenStack Cluster VLAN Pool'
            }
        }
        
        # Inicializar pools si no existen
        self._initialize_vlan_pools()
    
    def _initialize_vlan_pools(self):
        """Inicializa los pools de VLANs en la base de datos"""
        try:
            with self.lock:
                for infrastructure, config in self.vlan_pools.items():
                    for vlan_id in range(config['start'], config['end'] + 1):
                        # Verificar si la VLAN ya existe
                        existing = self.db.execute('''
                            SELECT vlan_id FROM vlan_pool 
                            WHERE vlan_id = ? AND infrastructure = ?
                        ''', (vlan_id, infrastructure)).fetchone()
                        
                        if not existing:
                            self.db.execute('''
                                INSERT INTO vlan_pool (
                                    vlan_id, infrastructure, state, 
                                    description, created_at
                                ) VALUES (?, ?, ?, ?, ?)
                            ''', (
                                vlan_id,
                                infrastructure, 
                                VLANState.AVAILABLE.value,
                                f'VLAN {vlan_id} for {infrastructure}',
                                datetime.datetime.utcnow().isoformat()
                            ))
                
                self.db.commit()
                logger.info("VLAN pools initialized successfully")
                
        except Exception as e:
            logger.error(f"Error initializing VLAN pools: {e}")
            self.db.rollback()
            raise
    
    def allocate_vlan(self, infrastructure: str, network_id: str, 
                     slice_id: str = None, description: str = None) -> Optional[int]:
        """
        Asigna una VLAN disponible del pool especificado
        
        Args:
            infrastructure: 'linux' o 'openstack'
            network_id: ID de la red que usará esta VLAN
            slice_id: ID del slice (opcional)
            description: Descripción del uso (opcional)
            
        Returns:
            VLAN ID asignada o None si no hay VLANs disponibles
        """
        if infrastructure not in self.vlan_pools:
            logger.error(f"Infrastructure '{infrastructure}' not supported")
            return None
        
        try:
            with self.lock:
                # Buscar primera VLAN disponible en el pool
                available_vlan = self.db.execute('''
                    SELECT vlan_id FROM vlan_pool 
                    WHERE infrastructure = ? AND state = ?
                    ORDER BY vlan_id ASC
                    LIMIT 1
                ''', (infrastructure, VLANState.AVAILABLE.value)).fetchone()
                
                if not available_vlan:
                    logger.warning(f"No available VLANs in {infrastructure} pool")
                    return None
                
                vlan_id = available_vlan['vlan_id']
                
                # Marcar VLAN como asignada
                self.db.execute('''
                    UPDATE vlan_pool SET 
                        state = ?,
                        network_id = ?,
                        slice_id = ?,
                        assigned_at = ?,
                        usage_description = ?
                    WHERE vlan_id = ? AND infrastructure = ?
                ''', (
                    VLANState.ALLOCATED.value,
                    network_id,
                    slice_id,
                    datetime.datetime.utcnow().isoformat(),
                    description or f'Network {network_id}'
                ))
                
                self.db.commit()
                logger.info(f"VLAN {vlan_id} allocated to network {network_id} in {infrastructure}")
                return vlan_id
                
        except Exception as e:
            logger.error(f"Error allocating VLAN: {e}")
            self.db.rollback()
            return None
    
    def release_vlan(self, vlan_id: int, infrastructure: str) -> bool:
        """
        Libera una VLAN para reutilización
        
        Args:
            vlan_id: ID de la VLAN a liberar
            infrastructure: Infraestructura de la VLAN
            
        Returns:
            True si se liberó correctamente, False en caso contrario
        """
        try:
            with self.lock:
                # Verificar que la VLAN esté asignada
                vlan_info = self.db.execute('''
                    SELECT vlan_id, state, network_id FROM vlan_pool 
                    WHERE vlan_id = ? AND infrastructure = ?
                ''', (vlan_id, infrastructure)).fetchone()
                
                if not vlan_info:
                    logger.warning(f"VLAN {vlan_id} not found in {infrastructure} pool")
                    return False
                
                if vlan_info['state'] != VLANState.ALLOCATED.value:
                    logger.warning(f"VLAN {vlan_id} is not allocated (state: {vlan_info['state']})")
                    return False
                
                # Liberar la VLAN
                self.db.execute('''
                    UPDATE vlan_pool SET 
                        state = ?,
                        network_id = NULL,
                        slice_id = NULL,
                        released_at = ?,
                        usage_description = NULL
                    WHERE vlan_id = ? AND infrastructure = ?
                ''', (
                    VLANState.AVAILABLE.value,
                    datetime.datetime.utcnow().isoformat(),
                    vlan_id,
                    infrastructure
                ))
                
                self.db.commit()
                logger.info(f"VLAN {vlan_id} released in {infrastructure}")
                return True
                
        except Exception as e:
            logger.error(f"Error releasing VLAN {vlan_id}: {e}")
            self.db.rollback()
            return False
    
    def release_vlan_by_network(self, network_id: str) -> bool:
        """
        Libera la VLAN asignada a una red específica
        
        Args:
            network_id: ID de la red
            
        Returns:
            True si se liberó correctamente, False en caso contrario
        """
        try:
            with self.lock:
                # Buscar la VLAN asignada a esta red
                vlan_info = self.db.execute('''
                    SELECT vlan_id, infrastructure FROM vlan_pool 
                    WHERE network_id = ? AND state = ?
                ''', (network_id, VLANState.ALLOCATED.value)).fetchone()
                
                if not vlan_info:
                    logger.warning(f"No allocated VLAN found for network {network_id}")
                    return False
                
                return self.release_vlan(vlan_info['vlan_id'], vlan_info['infrastructure'])
                
        except Exception as e:
            logger.error(f"Error releasing VLAN for network {network_id}: {e}")
            return False
    
    def release_slice_vlans(self, slice_id: str) -> int:
        """
        Libera todas las VLANs asignadas a un slice
        
        Args:
            slice_id: ID del slice
            
        Returns:
            Número de VLANs liberadas
        """
        try:
            with self.lock:
                # Buscar todas las VLANs del slice
                slice_vlans = self.db.execute('''
                    SELECT vlan_id, infrastructure FROM vlan_pool 
                    WHERE slice_id = ? AND state = ?
                ''', (slice_id, VLANState.ALLOCATED.value)).fetchall()
                
                released_count = 0
                for vlan in slice_vlans:
                    if self.release_vlan(vlan['vlan_id'], vlan['infrastructure']):
                        released_count += 1
                
                logger.info(f"Released {released_count} VLANs for slice {slice_id}")
                return released_count
                
        except Exception as e:
            logger.error(f"Error releasing VLANs for slice {slice_id}: {e}")
            return 0
    
    def get_pool_status(self, infrastructure: str = None) -> Dict:
        """
        Obtiene estadísticas del pool de VLANs
        
        Args:
            infrastructure: Infraestructura específica (opcional)
            
        Returns:
            Diccionario con estadísticas
        """
        try:
            stats = {}
            
            infrastructures = [infrastructure] if infrastructure else self.vlan_pools.keys()
            
            for infra in infrastructures:
                if infra not in self.vlan_pools:
                    continue
                
                # Contar VLANs por estado
                state_counts = {}
                for state in VLANState:
                    count = self.db.execute('''
                        SELECT COUNT(*) as count FROM vlan_pool 
                        WHERE infrastructure = ? AND state = ?
                    ''', (infra, state.value)).fetchone()
                    state_counts[state.value] = count['count']
                
                # Calcular estadísticas
                total = sum(state_counts.values())
                available = state_counts.get(VLANState.AVAILABLE.value, 0)
                allocated = state_counts.get(VLANState.ALLOCATED.value, 0)
                
                usage_percentage = (allocated / total * 100) if total > 0 else 0
                
                stats[infra] = {
                    'total_vlans': total,
                    'available': available,
                    'allocated': allocated,
                    'reserved': state_counts.get(VLANState.RESERVED.value, 0),
                    'error': state_counts.get(VLANState.ERROR.value, 0),
                    'usage_percentage': round(usage_percentage, 2),
                    'pool_range': f"{self.vlan_pools[infra]['start']}-{self.vlan_pools[infra]['end']}"
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting pool status: {e}")
            return {}
    
    def get_allocated_vlans(self, infrastructure: str = None, slice_id: str = None) -> List[Dict]:
        """
        Obtiene lista de VLANs asignadas
        
        Args:
            infrastructure: Filtrar por infraestructura (opcional)
            slice_id: Filtrar por slice (opcional)
            
        Returns:
            Lista de VLANs asignadas con sus detalles
        """
        try:
            query = '''
                SELECT vlan_id, infrastructure, network_id, slice_id, 
                       assigned_at, usage_description
                FROM vlan_pool 
                WHERE state = ?
            '''
            params = [VLANState.ALLOCATED.value]
            
            if infrastructure:
                query += ' AND infrastructure = ?'
                params.append(infrastructure)
            
            if slice_id:
                query += ' AND slice_id = ?'
                params.append(slice_id)
            
            query += ' ORDER BY infrastructure, vlan_id'
            
            vlans = self.db.execute(query, params).fetchall()
            return [dict(vlan) for vlan in vlans]
            
        except Exception as e:
            logger.error(f"Error getting allocated VLANs: {e}")
            return []
    
    def reserve_vlan_range(self, infrastructure: str, start_vlan: int, 
                          end_vlan: int, description: str = None) -> bool:
        """
        Reserva un rango de VLANs para uso especial
        
        Args:
            infrastructure: Infraestructura
            start_vlan: VLAN inicial del rango
            end_vlan: VLAN final del rango
            description: Descripción de la reserva
            
        Returns:
            True si se reservó correctamente, False en caso contrario
        """
        try:
            with self.lock:
                # Verificar que todas las VLANs del rango estén disponibles
                for vlan_id in range(start_vlan, end_vlan + 1):
                    vlan_state = self.db.execute('''
                        SELECT state FROM vlan_pool 
                        WHERE vlan_id = ? AND infrastructure = ?
                    ''', (vlan_id, infrastructure)).fetchone()
                    
                    if not vlan_state or vlan_state['state'] != VLANState.AVAILABLE.value:
                        logger.warning(f"VLAN {vlan_id} not available for reservation")
                        return False
                
                # Reservar todas las VLANs del rango
                for vlan_id in range(start_vlan, end_vlan + 1):
                    self.db.execute('''
                        UPDATE vlan_pool SET 
                            state = ?,
                            usage_description = ?,
                            assigned_at = ?
                        WHERE vlan_id = ? AND infrastructure = ?
                    ''', (
                        VLANState.RESERVED.value,
                        description or f'Reserved range {start_vlan}-{end_vlan}',
                        datetime.datetime.utcnow().isoformat(),
                        vlan_id,
                        infrastructure
                    ))
                
                self.db.commit()
                logger.info(f"Reserved VLAN range {start_vlan}-{end_vlan} in {infrastructure}")
                return True
                
        except Exception as e:
            logger.error(f"Error reserving VLAN range: {e}")
            self.db.rollback()
            return False
    
    def get_vlan_info(self, vlan_id: int, infrastructure: str) -> Optional[Dict]:
        """
        Obtiene información detallada de una VLAN específica
        
        Args:
            vlan_id: ID de la VLAN
            infrastructure: Infraestructura
            
        Returns:
            Diccionario con información de la VLAN o None
        """
        try:
            vlan_info = self.db.execute('''
                SELECT * FROM vlan_pool 
                WHERE vlan_id = ? AND infrastructure = ?
            ''', (vlan_id, infrastructure)).fetchone()
            
            return dict(vlan_info) if vlan_info else None
            
        except Exception as e:
            logger.error(f"Error getting VLAN info: {e}")
            return None