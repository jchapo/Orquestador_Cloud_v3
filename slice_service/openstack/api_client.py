import logging
import time
from typing import Dict, List, Any, Optional

from keystoneauth1 import loading, session
from keystoneauth1.identity import v3
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
from glanceclient import Client as glance_client
from cinderclient import client as cinder_client

logger = logging.getLogger(__name__)

class OpenStackAPIClient:
    def __init__(self, auth_config: Dict[str, str]):
        self.auth_config = auth_config
        self._session = None
        self._nova = None
        self._neutron = None
        self._glance = None
        self._cinder = None
        
    @property
    def session(self):
        if self._session is None:
            auth = v3.Password(
                auth_url=self.auth_config['auth_url'],
                username=self.auth_config['username'],
                password=self.auth_config['password'],
                project_name=self.auth_config['project_name'],
                user_domain_name=self.auth_config['user_domain_name'],
                project_domain_name=self.auth_config['project_domain_name']
            )
            self._session = session.Session(auth=auth)
        return self._session
    
    @property
    def nova(self):
        if self._nova is None:
            self._nova = nova_client.Client(
                version='2.1',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne')
            )
        return self._nova
    
    @property
    def neutron(self):
        if self._neutron is None:
            self._neutron = neutron_client.Client(
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne')
            )
        return self._neutron
    
    @property
    def glance(self):
        if self._glance is None:
            self._glance = glance_client(
                '2',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne')
            )
        return self._glance
    
    @property
    def cinder(self):
        if self._cinder is None:
            self._cinder = cinder_client.Client(
                '3',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne')
            )
        return self._cinder
    
    def list_servers(self, detailed=True) -> List[Any]:
        return self.nova.servers.list(detailed=detailed)
    
    def create_server(self, name: str, image_id: str, flavor_id: str,
                     network_id: str = None, security_groups: List[str] = None,
                     availability_zone: str = None, user_data: str = None) -> Any:
        
        nics = []
        if network_id:
            nics = [{'net-id': network_id}]
        
        if security_groups is None:
            security_groups = ['default']
        
        server = self.nova.servers.create(
            name=name,
            image=image_id,
            flavor=flavor_id,
            nics=nics,
            security_groups=security_groups,
            availability_zone=availability_zone,
            userdata=user_data
        )
        
        return server
    
    def delete_server(self, server_id: str):
        self.nova.servers.delete(server_id)
    
    def get_server(self, server_id: str) -> Any:
        return self.nova.servers.get(server_id)
    
    def wait_for_server_active(self, server_id: str, timeout: int = 300) -> bool:
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            server = self.get_server(server_id)
            if server.status == 'ACTIVE':
                return True
            elif server.status == 'ERROR':
                raise Exception(f"Server {server_id} entered ERROR state")
            
            time.sleep(5)
        
        return False
    
    def list_networks(self) -> List[Dict]:
        return self.neutron.list_networks()['networks']
    
    def create_network(self, name: str, provider_network_type: str = 'vlan',
                      provider_physical_network: str = 'physnet1',
                      provider_segmentation_id: int = None,
                      shared: bool = False) -> Dict:
        network_data = {
            'network': {
                'name': name,
                'admin_state_up': True,
                'shared': shared
            }
        }
        
        if provider_network_type == 'vlan':
            network_data['network'].update({
                'provider:network_type': provider_network_type,
                'provider:physical_network': provider_physical_network
            })
            if provider_segmentation_id:
                network_data['network']['provider:segmentation_id'] = provider_segmentation_id
        
        return self.neutron.create_network(network_data)['network']
    
    def delete_network(self, network_id: str):
        self.neutron.delete_network(network_id)
    
    def create_subnet(self, network_id: str, cidr: str, name: str = None,
                     gateway_ip: str = None, enable_dhcp: bool = True,
                     dns_nameservers: List[str] = None) -> Dict:
        subnet_data = {
            'subnet': {
                'network_id': network_id,
                'cidr': cidr,
                'ip_version': 4,
                'enable_dhcp': enable_dhcp
            }
        }
        
        if name:
            subnet_data['subnet']['name'] = name
        if gateway_ip:
            subnet_data['subnet']['gateway_ip'] = gateway_ip
        if dns_nameservers:
            subnet_data['subnet']['dns_nameservers'] = dns_nameservers
        
        return self.neutron.create_subnet(subnet_data)['subnet']
    
    def create_port(self, network_id: str, name: str = None,
                   fixed_ips: List[Dict] = None, security_groups: List[str] = None) -> Dict:
        port_data = {
            'port': {
                'network_id': network_id,
                'admin_state_up': True
            }
        }
        
        if name:
            port_data['port']['name'] = name
        if fixed_ips:
            port_data['port']['fixed_ips'] = fixed_ips
        if security_groups:
            port_data['port']['security_groups'] = security_groups
        
        return self.neutron.create_port(port_data)['port']
    
    def delete_port(self, port_id: str):
        self.neutron.delete_port(port_id)
    
    def create_security_group(self, name: str, description: str = None) -> Dict:
        sg_data = {
            'security_group': {
                'name': name,
                'description': description or f'Security group {name}'
            }
        }
        return self.neutron.create_security_group(sg_data)['security_group']
    
    def add_security_group_rule(self, security_group_id: str, direction: str = 'ingress',
                               ethertype: str = 'IPv4', protocol: str = None,
                               port_range_min: int = None, port_range_max: int = None,
                               remote_ip_prefix: str = None) -> Dict:
        rule_data = {
            'security_group_rule': {
                'security_group_id': security_group_id,
                'direction': direction,
                'ethertype': ethertype
            }
        }
        
        if protocol:
            rule_data['security_group_rule']['protocol'] = protocol
        if port_range_min:
            rule_data['security_group_rule']['port_range_min'] = port_range_min
        if port_range_max:
            rule_data['security_group_rule']['port_range_max'] = port_range_max
        if remote_ip_prefix:
            rule_data['security_group_rule']['remote_ip_prefix'] = remote_ip_prefix
        
        return self.neutron.create_security_group_rule(rule_data)['security_group_rule']
    
    def list_images(self) -> List[Any]:
        return list(self.glance.images.list())
    
    def get_image(self, image_id: str) -> Any:
        return self.glance.images.get(image_id)
    
    def find_image(self, name: str) -> Optional[Any]:
        images = self.list_images()
        for image in images:
            if image.name == name:
                return image
        return None
    
    def list_flavors(self) -> List[Any]:
        return self.nova.flavors.list()
    
    def get_flavor(self, flavor_id: str) -> Any:
        return self.nova.flavors.get(flavor_id)
    
    def find_flavor(self, name: str) -> Optional[Any]:
        flavors = self.list_flavors()
        for flavor in flavors:
            if flavor.name == name:
                return flavor
        return None
    
    def create_flavor(self, name: str, ram: int, vcpus: int, disk: int) -> Any:
        return self.nova.flavors.create(
            name=name,
            ram=ram,
            vcpus=vcpus,
            disk=disk
        )