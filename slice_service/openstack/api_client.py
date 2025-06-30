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
            # Usar endpoint directo via túnel SSH
            self._nova = nova_client.Client(
                version='2.1',
                session=self.session,
                region_name=self.auth_config.get('region_name', 'RegionOne'),
                endpoint_override='http://localhost:18774'  # ← Usar túnel SSH
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
            self.nova.servers.list()
            services['nova'] = {'available': True, 'status': 'healthy'}
        except Exception as e:
            services['nova'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        # Test Neutron
        try:
            self.neutron.list_networks()
            services['neutron'] = {'available': True, 'status': 'healthy'}
        except Exception as e:
            services['neutron'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        # Test Glance
        try:
            list(self.glance.images.list())
            services['glance'] = {'available': True, 'status': 'healthy'}
        except Exception as e:
            services['glance'] = {'available': False, 'status': str(e)}
            overall_health = False
        
        return {
            'overall': overall_health,
            'services': services
        }
