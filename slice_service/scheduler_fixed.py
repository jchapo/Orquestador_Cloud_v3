#!/usr/bin/env python3
"""
VM Scheduler con algoritmos avanzados de placement - CORREGIDO
"""

from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)

class VMScheduler:
    def __init__(self):
        self.placement_policies = {
            'balanced': self._balanced_placement,
            'consolidated': self._consolidated_placement,
            'distributed': self._distributed_placement,
            'energy_efficient': self._energy_efficient_placement
        }
    
    def schedule_slice(self, slice_config: Dict, resources: List[Dict], 
                      policy: str = 'balanced') -> Dict:
        """Programa un slice completo"""
        
        if policy not in self.placement_policies:
            policy = 'balanced'
        
        return self.placement_policies[policy](slice_config, resources)
    
    def find_placement(self, slice_config: Dict, available_servers: Dict) -> Dict:
        """Encuentra placement para un slice"""
        infrastructure = slice_config.get('infrastructure', 'linux')
        
        if infrastructure == 'openstack':
            placement = {}
            zones = list(set(s.get('availability_zone', 'nova') 
                            for s in available_servers.values()))
            
            for i, vm in enumerate(slice_config.get('vms', [])):
                zone = zones[i % len(zones)] if zones else 'nova'
                placement[vm['name']] = {
                    'zone': zone,
                    'infrastructure': 'openstack'
                }
            
            return placement
        else:
            return self._linux_placement(slice_config, available_servers)
    
    def _balanced_placement(self, slice_config: Dict, resources: List[Dict]) -> Dict:
        """Placement balanceado"""
        placement = {}
        
        # Ordenar servidores por utilización (menor primero)
        sorted_servers = sorted(resources, 
            key=lambda x: x.get('used_vcpus', 0) / x.get('total_vcpus', 1))
        
        for i, vm in enumerate(slice_config.get('vms', [])):
            server = sorted_servers[i % len(sorted_servers)]
            placement[vm['name']] = {
                'server': server['hostname'],
                'policy': 'balanced'
            }
        
        return {'placement': placement, 'policy': 'balanced'}
    
    def _consolidated_placement(self, slice_config: Dict, resources: List[Dict]) -> Dict:
        """Placement consolidado"""
        placement = {}
        
        # Usar el servidor más utilizado primero
        sorted_servers = sorted(resources, 
            key=lambda x: x.get('used_vcpus', 0) / x.get('total_vcpus', 1), 
            reverse=True)
        
        for vm in slice_config.get('vms', []):
            placement[vm['name']] = {
                'server': sorted_servers[0]['hostname'],
                'policy': 'consolidated'
            }
        
        return {'placement': placement, 'policy': 'consolidated'}
    
    def _distributed_placement(self, slice_config: Dict, resources: List[Dict]) -> Dict:
        """Placement distribuido"""
        placement = {}
        
        for i, vm in enumerate(slice_config.get('vms', [])):
            server = resources[i % len(resources)]
            placement[vm['name']] = {
                'server': server['hostname'],
                'policy': 'distributed'
            }
        
        return {'placement': placement, 'policy': 'distributed'}
    
    def _energy_efficient_placement(self, slice_config: Dict, resources: List[Dict]) -> Dict:
        """Placement que minimiza consumo energético"""
        placement = {}
        
        # Ordenar servidores por eficiencia energética (más utilizados primero)
        sorted_servers = sorted(resources, 
            key=lambda x: x.get('used_vcpus', 0) / x.get('total_vcpus', 1), 
            reverse=True)
        
        for vm in slice_config.get('vms', []):
            for server in sorted_servers:
                if self._can_place_vm(vm, server):
                    placement[vm['name']] = {
                        'server': server['hostname'],
                        'efficiency_score': self._calculate_efficiency(server)
                    }
                    break
        
        return {'placement': placement, 'policy': 'energy_efficient'}
    
    def _linux_placement(self, slice_config: Dict, available_servers: Dict) -> Dict:
        """Placement específico para Linux"""
        placement = {}
        servers = list(available_servers.values())
        
        for i, vm in enumerate(slice_config.get('vms', [])):
            server = servers[i % len(servers)]
            placement[vm['name']] = {
                'server': server['hostname'],
                'infrastructure': 'linux'
            }
        
        return placement
    
    def _can_place_vm(self, vm: Dict, server: Dict) -> bool:
        """Verifica si una VM puede ser colocada en un servidor"""
        vm_vcpus = vm.get('vcpus', 1)
        vm_ram = vm.get('ram', 512)
        
        server_available_vcpus = server.get('available_vcpus', server.get('total_vcpus', 0))
        server_available_ram = server.get('available_ram', server.get('total_ram', 0))
        
        return (server_available_vcpus >= vm_vcpus and 
                server_available_ram >= vm_ram)
    
    def _calculate_efficiency(self, server: Dict) -> float:
        """Calcula score de eficiencia energética"""
        used_ratio = server.get('used_vcpus', 0) / server.get('total_vcpus', 1)
        return used_ratio
    
    def validate_slice_config(self, slice_config: Dict) -> bool:
        """Valida configuración de slice"""
        if not slice_config.get('name'):
            raise ValueError("Slice name is required")
        
        vms = slice_config.get('vms', [])
        if not vms:
            raise ValueError("At least one VM is required")
        
        for vm in vms:
            if not vm.get('name'):
                raise ValueError("VM name is required")
            if not vm.get('flavor') and not vm.get('vcpus'):
                raise ValueError("VM flavor or vcpus specification is required")
        
        return True
