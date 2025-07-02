import logging
import time
import requests
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
            # Usar endpoint directo via túnel SSH
            self._nova = nova_client.Client(
                version='2.1',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne'),
                endpoint_override='http://localhost:18774/v2.1'  # ← Incluir v2.1
            )
        return self._nova
    
    @property
    def neutron(self):
        if self._neutron is None:
            # Usar endpoint directo via túnel SSH
            self._neutron = neutron_client.Client(
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne'),
                endpoint_override='http://localhost:19696'  # ← Usar túnel SSH
            )
        return self._neutron
    
    @property
    def glance(self):
        if self._glance is None:
            # Usar endpoint directo via túnel SSH
            self._glance = glance_client(
                '2',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne'),
                endpoint_override='http://localhost:19292'  # ← Usar túnel SSH
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

    def authenticate(self) -> bool:
        """Verificar autenticación"""
        try:
            token = self.session.get_token()
            return bool(token)
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def _get_nova_headers(self):
        """Obtener headers para API Nova"""
        token = self.session.get_token()
        return {
            'X-Auth-Token': token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def safe_flavors_list_api(self):
        """Método directo con API REST para listar flavors"""
        try:
            headers = self._get_nova_headers()
            # Usar URL v2.1 correcta
            response = requests.get('http://localhost:18774/v2.1/flavors', headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"🔍 Raw flavors response: {data}")
                
                # Manejar diferentes estructuras de respuesta
                if 'flavors' in data:
                    return data['flavors']
                elif isinstance(data, list):
                    return data
                else:
                    return []
            else:
                print(f"❌ Error en flavors API: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"API flavors failed: {e}")
            return []

    def safe_servers_list_api(self):
        """Método directo con API REST para listar servidores"""
        try:
            headers = self._get_nova_headers()
            # Usar URL v2.1 correcta
            response = requests.get('http://localhost:18774/v2.1/servers', headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"🔍 Raw servers response: {data}")
                
                # Manejar diferentes estructuras de respuesta
                if 'servers' in data:
                    return data['servers']
                elif isinstance(data, list):
                    return data
                else:
                    return []
            else:
                print(f"❌ Error en servers API: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"API servers failed: {e}")
            return []

    def safe_servers_list(self):
        """Método seguro para listar servidores"""
        # Intentar primero con API directa
        servers = self.safe_servers_list_api()
        if servers:
            return [type('Server', (), {'id': s.get('id', 'unknown'), 'name': s.get('name', 'unnamed')}) for s in servers]
        
        # Fallback al método original
        try:
            return self.nova.servers.list(detailed=False)
        except Exception as e:
            logger.error(f"All servers methods failed: {e}")
            return []

    def safe_flavors_list(self):
        """Método seguro para listar flavors"""
        # Intentar primero con API directa
        flavors = self.safe_flavors_list_api()
        if flavors:
            return [type('Flavor', (), {
                'id': f.get('id', 'unknown'), 
                'name': f.get('name', 'unnamed'),
                'vcpus': f.get('vcpus', 0),
                'ram': f.get('ram', 0)
            }) for f in flavors]
        
        # Fallback al método original
        try:
            return self.nova.flavors.list()
        except Exception as e:
            logger.error(f"All flavors methods failed: {e}")
            return []

    def health_check(self) -> Dict[str, Any]:
        """Health check de servicios OpenStack"""
        services = {}
        overall_health = True
        
        # Test Keystone
        try:
            token = self.session.get_token()
            services['keystone'] = {'available': True, 'status': 'healthy'}
        except Exception as e:
            services['keystone'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        # Test Nova
        try:
            flavors = self.safe_flavors_list()
            servers = self.safe_servers_list()
            services['nova'] = {
                'available': True, 
                'status': 'healthy', 
                'flavors': len(flavors),
                'servers': len(servers)
            }
        except Exception as e:
            services['nova'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        # Test Neutron
        try:
            networks = self.neutron.list_networks()['networks']
            services['neutron'] = {'available': True, 'status': 'healthy', 'networks': len(networks)}
        except Exception as e:
            services['neutron'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        # Test Glance
        try:
            images = list(self.glance.images.list())
            services['glance'] = {'available': True, 'status': 'healthy', 'images': len(images)}
        except Exception as e:
            services['glance'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        return {
            'overall': overall_health,
            'services': services
        }

    def create_server(self, name, flavor, image, networks=None):
        """Crear servidor usando API directa"""
        try:
            headers = self._get_nova_headers()
            
            server_data = {
                "server": {
                    "name": name,
                    "flavorRef": flavor,
                    "imageRef": image
                }
            }
            
            if networks:
                server_data["server"]["networks"] = networks
            
            # Usar URL v2.1 correcta
            response = requests.post(
                'http://localhost:18774/v2.1/servers',
                headers=headers,
                json=server_data,
                timeout=30
            )
            
            if response.status_code in [200, 202]:
                return response.json()
            else:
                logger.error(f"Create server failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Create server exception: {e}")
            return None
