#!/usr/bin/env python3
"""
Slice Service Mock para pruebas
"""

from datetime import datetime, timedelta
import uuid

class SliceService:
    def __init__(self):
        self.active_reservations = {}
    
    def create_slice_with_reservation(self, slice_config: dict, resources: dict) -> dict:
        """Crea slice con reserva de recursos"""
        reservation_id = f"res-{uuid.uuid4().hex[:8]}"
        
        # Simular reserva de recursos
        reservation = self.reserve_resources(slice_config, resources)
        
        try:
            # Simular despliegue
            result = self.deploy_slice(slice_config)
            
            return {
                'status': 'deployed',
                'slice_id': result['slice_id'],
                'resources_reserved': True,
                'reservation_id': reservation['reservation_id']
            }
        except Exception as e:
            # Rollback en caso de error
            self.release_reservation(reservation['reservation_id'])
            raise e
    
    def reserve_resources(self, slice_config: dict, resources: dict) -> dict:
        """Reserva recursos temporalmente"""
        reservation_id = f"res-{uuid.uuid4().hex[:8]}"
        
        # Calcular recursos necesarios
        total_vcpus = sum(vm.get('vcpus', 1) for vm in slice_config.get('vms', []))
        total_ram = sum(vm.get('ram', 512) for vm in slice_config.get('vms', []))
        
        reservation = {
            'reservation_id': reservation_id,
            'expires_at': datetime.now() + timedelta(minutes=15),
            'reserved_resources': {
                'vcpus': total_vcpus,
                'ram': total_ram
            }
        }
        
        self.active_reservations[reservation_id] = reservation
        return reservation
    
    def deploy_slice(self, slice_config: dict) -> dict:
        """Simula despliegue de slice"""
        # Simular posible fallo
        if slice_config.get('name') == 'rollback-test':
            raise Exception("VM creation failed")
        
        return {
            'slice_id': f"slice-{uuid.uuid4().hex[:8]}",
            'status': 'deployed'
        }
    
    def release_reservation(self, reservation_id: str) -> bool:
        """Libera reserva de recursos"""
        if reservation_id in self.active_reservations:
            del self.active_reservations[reservation_id]
            return True
        return False
    
    def create_slice(self, user_profile: dict, slice_config: dict) -> dict:
        """Crea slice completo"""
        return {
            'status': 'deployed',
            'slice_id': f"slice-{uuid.uuid4().hex[:8]}",
            'user': user_profile['username'],
            'infrastructure': slice_config.get('infrastructure', 'linux')
        }
    
    def authenticate_user(self, user_profile: dict) -> bool:
        """Mock de autenticación"""
        return True
    
    def validate_permissions(self, user_profile: dict, action: str) -> bool:
        """Mock de validación de permisos"""
        return True
    
    def check_resource_quotas(self, user_profile: dict, slice_config: dict) -> bool:
        """Mock de verificación de quotas"""
        return True
