"""
Configuration for PUCP Cloud Orchestrator
"""
import os

class Config:
    # Security
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025-change-in-production')
    
    # Service URLs - update these based on your deployment
    AUTH_SERVICE_URL = os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001')
    SLICE_SERVICE_URL = os.getenv('SLICE_SERVICE_URL', 'http://localhost:5002')
    TEMPLATE_SERVICE_URL = os.getenv('TEMPLATE_SERVICE_URL', 'http://localhost:5003')
    NETWORK_SERVICE_URL = os.getenv('NETWORK_SERVICE_URL', 'http://localhost:5004')
    IMAGE_SERVICE_URL = os.getenv('IMAGE_SERVICE_URL', 'http://localhost:5005')
    
    # Gateway settings
    HOST = '0.0.0.0'
    PORT = 5000
    DEBUG = False
    
    # Infrastructure settings (based on your project specs)
    LINUX_CLUSTER_SUBNET = '10.60.1.0/24'
    OPENSTACK_CLUSTER_SUBNET = '10.60.2.0/24'
    
    # VM Access ports (from your project document)
    VM_ACCESS_PORTS = {
        'linux': {
            'server1': 5811,
            'server2': 5812,
            'server3': 5813,
            'server4': 5814,
            'ovs1': 5815
        },
        'openstack': {
            'headnode': 5821,
            'worker1': 5822,
            'worker2': 5823,
            'worker3': 5824,
            'ovs2': 5825
        }
    }

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
