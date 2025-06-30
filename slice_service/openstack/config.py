import os
import json

class OpenStackConfig:
    def __init__(self):
        self.config = {
            # Usar túneles SSH en lugar de IPs directas
            'auth_url': 'http://localhost:15000/v3',  # Keystone via túnel
            'username': 'admin',
            'password': 'admin123',
            'project_name': 'admin',
            'user_domain_name': 'Default',
            'project_domain_name': 'Default',
            'region_name': 'RegionOne',
            
            # Endpoints usando túneles SSH
            'nova_endpoint': 'http://localhost:18774/v2.1',  # Nova via túnel
            'neutron_endpoint': 'http://localhost:19696',     # Neutron via túnel
            'glance_endpoint': 'http://localhost:19292',      # Glance via túnel
            
            # Configuración de red
            'provider_network': 'external',
            'external_network': 'external',
            'physical_network': 'physnet1',
            'vlan_range': '200:299',
            
            # Flavors disponibles
            'flavors': {
                'small': {'vcpus': 1, 'ram': 512, 'disk': 10},
                'medium': {'vcpus': 2, 'ram': 1024, 'disk': 20},
                '512MBRAM_1VCPUs_4GBRoot': {'vcpus': 1, 'ram': 512, 'disk': 4}
            }
        }
    
    def get_auth_config(self):
        return {
            'auth_url': self.config['auth_url'],
            'username': self.config['username'],
            'password': self.config['password'],
            'project_name': self.config['project_name'],
            'user_domain_name': self.config['user_domain_name'],
            'project_domain_name': self.config['project_domain_name'],
            'region_name': self.config['region_name']
        }
    
    def get_endpoints(self):
        return {
            'nova': self.config['nova_endpoint'],
            'neutron': self.config['neutron_endpoint'], 
            'glance': self.config['glance_endpoint']
        }
    
    @property
    def flavors(self):
        return self.config['flavors']
