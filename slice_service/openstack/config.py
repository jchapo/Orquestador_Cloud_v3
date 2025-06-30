import json
import os

class OpenStackConfig:
    def __init__(self, config_file="/opt/pucp-orchestrator/openstack_cluster_config.json"):
        self.config_file = config_file
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        self.auth = self.config['auth']
    
    def get_auth_config(self):
        """Obtener configuración de autenticación"""
        return {
            'auth_url': self.auth['auth_url'],
            'username': self.auth['username'], 
            'password': self.auth['password'],
            'project_name': self.auth['project_name'],
            'user_domain_name': self.auth['user_domain_name'],
            'project_domain_name': self.auth['project_domain_name'],
            'region_name': self.auth.get('region_name', 'RegionOne')
        }
    
    def get_compute_nodes(self):
        """Obtener lista de nodos de cómputo"""
        return self.config['compute_nodes']
    
    def get_network_config(self):
        """Obtener configuración de red"""
        return self.config['network_config']
        
    def get_flavors(self):
        """Obtener flavors disponibles"""
        return self.config.get('flavors', {})
        
    def get_images(self):
        """Obtener imágenes disponibles"""
        return self.config.get('images', {})
