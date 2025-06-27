import os
import json
import logging

logger = logging.getLogger(__name__)

class OpenStackConfig:
    
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'openstack_cluster_config.json'
            )
        
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.auth = self.config['auth']
        self.compute_nodes = self.config['compute_nodes']
        self.network_config = self.config['network_config']
        self.flavors = self.config['flavors']
        self.images = self.config['images']
        
    def get_auth_config(self):
        return {
            'auth_url': self.auth['auth_url'],
            'username': self.auth['username'],
            'password': self.auth['password'],
            'project_name': self.auth['project_name'],
            'user_domain_name': self.auth['user_domain_name'],
            'project_domain_name': self.auth['project_domain_name'],
            'region_name': self.auth.get('region_name', 'RegionOne')
        }
    
    def get_availability_zones(self):
        zones = set()
        for node in self.compute_nodes.values():
            if node['role'] == 'compute':
                zones.add(node.get('availability_zone', 'nova'))
        return list(zones)
    
    def get_vlan_range(self):
        vlan_range = self.network_config['vlan_range']
        start, end = vlan_range.split(':')
        return int(start), int(end)