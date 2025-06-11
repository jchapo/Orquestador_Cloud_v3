# slice_service/scheduler.py
#!/usr/bin/env python3
"""
VM Scheduler con algoritmos avanzados de placement
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
    
    def _energy_efficient_placement(self, slice_config: Dict, 
                                  resources: List[Dict]) -> Dict:
        """Placement que minimiza consumo energético"""
        # Algoritmo que consolida VMs para poder apagar servidores
        placement = {}
        
        # Ordenar servidores por eficiencia energética
        sorted_servers = sorted(resources, 
            key=lambda x: x['used_vcpus'] / x['total_vcpus'], 
            reverse=True)
        
        for vm in slice_config['vms']:
            for server in sorted_servers:
                if self._can_place_vm(vm, server):
                    placement[vm['name']] = {
                        'server': server['hostname'],
                        'efficiency_score': self._calculate_efficiency(server)
                    }
                    self._update_server_resources(server, vm)
                    break
        
        return {'placement': placement, 'policy': 'energy_efficient'}