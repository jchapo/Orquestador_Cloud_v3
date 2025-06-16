#!/usr/bin/env python3
"""
Cliente base para APIs de OpenStack
Implementa autenticación y llamadas básicas a los servicios
"""

import requests
import json
import logging
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from config.openstack_config import OPENSTACK_CONFIG

logger = logging.getLogger(__name__)

class OpenStackAPIClient:
    """Cliente base para APIs de OpenStack"""
    
    def __init__(self):
        self.config = OPENSTACK_CONFIG
        self.endpoints = self.config['endpoints']
        self.admin_creds = self.config['admin_credentials']
        
        # Tokens y sesión
        self.auth_token = None
        self.token_expires = None
        self.project_id = None
        self.session = requests.Session()
        
        # Cache de servicios
        self.service_catalog = {}
        
    def authenticate(self) -> bool:
        """Autenticación con Keystone"""
        logger.info("Authenticating with OpenStack Keystone...")
        
        auth_url = self.endpoints['keystone']['public']
        auth_data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.admin_creds['username'],
                            "domain": {"name": self.admin_creds['domain_name']},
                            "password": self.admin_creds['password']
                        }
                    }
                },
                "scope": {
                    "project": {
                        "name": self.admin_creds['project_name'],
                        "domain": {"name": self.admin_creds['domain_name']}
                    }
                }
            }
        }
        
        try:
            response = self.session.post(
                f"{auth_url}/auth/tokens",
                json=auth_data,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 201:
                self.auth_token = response.headers.get('X-Subject-Token')
                token_data = response.json()
                
                # Extraer información del token
                self.project_id = token_data['token']['project']['id']
                expires_at = token_data['token']['expires_at']
                self.token_expires = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                
                # Guardar catálogo de servicios
                self.service_catalog = {
                    service['type']: service['endpoints']
                    for service in token_data['token']['catalog']
                }
                
                # Configurar headers para futuras llamadas
                self.session.headers.update({
                    'X-Auth-Token': self.auth_token,
                    'Content-Type': 'application/json'
                })
                
                logger.info("✅ OpenStack authentication successful")
                logger.info(f"   Project ID: {self.project_id}")
                logger.info(f"   Token expires: {self.token_expires}")
                
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def is_token_valid(self) -> bool:
        """Verifica si el token sigue siendo válido"""
        if not self.auth_token or not self.token_expires:
            return False
        
        # Renovar token si expira en los próximos 5 minutos
        return datetime.utcnow() < (self.token_expires - timedelta(minutes=5))
    
    def ensure_authenticated(self) -> bool:
        """Asegura que tenemos un token válido"""
        if not self.is_token_valid():
            return self.authenticate()
        return True
    
    def get_service_endpoint(self, service_type: str, interface: str = 'public') -> Optional[str]:
        """Obtiene endpoint de un servicio del catálogo"""
        if service_type in self.service_catalog:
            for endpoint in self.service_catalog[service_type]:
                if endpoint['interface'] == interface:
                    return endpoint['url']
        return None
    
    def make_request(self, method: str, service_type: str, path: str, 
                    data: Optional[Dict] = None, interface: str = 'public') -> requests.Response:
        """Hace una llamada HTTP a un servicio de OpenStack"""
        
        if not self.ensure_authenticated():
            raise Exception("Failed to authenticate with OpenStack")
        
        endpoint = self.get_service_endpoint(service_type, interface)
        if not endpoint:
            raise Exception(f"Endpoint not found for service {service_type}")
        
        url = f"{endpoint.rstrip('/')}/{path.lstrip('/')}"
        
        logger.debug(f"{method.upper()} {url}")
        
        kwargs = {'timeout': 30}
        if data:
            kwargs['json'] = data
        
        response = self.session.request(method, url, **kwargs)
        
        logger.debug(f"Response: {response.status_code}")
        
        return response
    
    def health_check(self) -> Dict[str, Any]:
        """Verifica estado de los servicios principales"""
        services = ['identity', 'compute', 'network', 'image']
        health_status = {
            'overall': True,
            'services': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        for service in services:
            try:
                if service == 'identity':
                    # Keystone - verificar autenticación
                    status = self.ensure_authenticated()
                elif service == 'compute':
                    # Nova - listar flavors
                    response = self.make_request('GET', 'compute', 'flavors')
                    status = response.status_code == 200
                elif service == 'network':
                    # Neutron - listar redes
                    response = self.make_request('GET', 'network', 'v2.0/networks')
                    status = response.status_code == 200
                elif service == 'image':
                    # Glance - listar imágenes
                    response = self.make_request('GET', 'image', 'v2/images')
                    status = response.status_code == 200
                
                health_status['services'][service] = {
                    'status': 'healthy' if status else 'unhealthy',
                    'available': status
                }
                
                if not status:
                    health_status['overall'] = False
                    
            except Exception as e:
                logger.error(f"Health check failed for {service}: {e}")
                health_status['services'][service] = {
                    'status': 'error',
                    'error': str(e),
                    'available': False
                }
                health_status['overall'] = False
        
        return health_status