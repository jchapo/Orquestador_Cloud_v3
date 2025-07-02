#!/usr/bin/env python3
"""
Orchestrator Mock para pruebas
"""

class Orchestrator:
    def __init__(self):
        self.role_infrastructure_mapping = {
            'student': 'linux',
            'professor': 'openstack',  # Puede usar ambos
            'researcher': 'openstack',
            'admin': 'openstack'
        }
    
    def decide_infrastructure(self, user_profile: dict, slice_config: dict, mode: str = 'auto') -> dict:
        """Decide qué infraestructura usar"""
        user_role = user_profile.get('role', 'student')
        
        if mode == 'manual':
            # Respetar selección manual
            infrastructure = slice_config.get('infrastructure', 'linux')
            return {
                'infrastructure': infrastructure,
                'zone': 'student' if infrastructure == 'linux' else 'research',
                'manual_override': True,
                'recommended_infrastructure': self.role_infrastructure_mapping.get(user_role, 'linux'),
                'respects_manual_selection': True,
                'decision_mode': 'manual'
            }
        
        # Modo automático
        recommended = self.role_infrastructure_mapping.get(user_role, 'linux')
        
        return {
            'infrastructure': recommended,
            'zone': 'student' if recommended == 'linux' else 'research',
            'placement_success': True,
            'decision_mode': 'auto',
            'resource_optimization': True
        }
    
    def select_driver(self, infrastructure: str):
        """Mock de select_driver"""
        class MockDriver:
            def __init__(self, infra_type):
                self.type = infra_type
        
        return MockDriver(infrastructure)
    
    def validate_and_adjust_zone(self, slice_config: dict, resources: dict) -> dict:
        """Valida y ajusta zonas"""
        requested_zone = slice_config.get('zone', 'nova')
        valid_zones = ['student', 'research', 'nova']
        
        if requested_zone not in valid_zones:
            # Usar zona por defecto
            default_zone = 'research' if slice_config.get('infrastructure') == 'openstack' else 'student'
            slice_config['zone'] = default_zone
        
        return slice_config
    
    def recommend_infrastructure(self, vm_request: dict, resource_status: dict) -> dict:
        """Recomienda infraestructura basada en recursos"""
        linux_resources = resource_status.get('linux', {})
        openstack_resources = resource_status.get('openstack', {})
        
        # Calcular requerimientos de VMs
        total_vcpus_needed = sum(vm.get('vcpus', 1) for vm in vm_request.get('vms', []))
        total_ram_needed = sum(vm.get('ram', 512) for vm in vm_request.get('vms', []))
        
        # Verificar disponibilidad
        linux_can_handle = (
            linux_resources.get('available_vcpus', 0) >= total_vcpus_needed and
            linux_resources.get('available_ram', 0) >= total_ram_needed
        )
        
        openstack_can_handle = (
            openstack_resources.get('available_vcpus', 0) >= total_vcpus_needed and
            openstack_resources.get('available_ram', 0) >= total_ram_needed
        )
        
        if openstack_can_handle and not linux_can_handle:
            return {
                'recommended': 'openstack',
                'reasons': ['resource_availability', 'performance']
            }
        elif linux_can_handle:
            return {
                'recommended': 'linux',
                'reasons': ['resource_availability', 'cost_efficiency']
            }
        else:
            return {
                'recommended': None,
                'reasons': ['insufficient_resources']
            }
