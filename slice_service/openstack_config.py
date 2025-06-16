#!/usr/bin/env python3
"""
Configuración del cluster OpenStack PUCP
Basado en la topología del documento del curso
"""

# Configuración según tu documento del curso
OPENSTACK_CONFIG = {
    'keystone_url': 'http://headnode:5000/v3',
    'nova_url': 'http://headnode:8774/v2.1',
    'neutron_url': 'http://headnode:9696/v2.0',
    'glance_url': 'http://headnode:9292/v2',
    'username': 'admin',
    'password': os.getenv('ADMIN_PASS', 'tu_admin_password_aqui'),
    'project_name': 'admin',
    'domain_name': 'Default'
},
    
    # Nodos del cluster (según documento)
    'nodes': {
        'headnode': {
            'ip': '10.60.2.21',  # Mapeo según tu topología
            'mgmt_ip': '192.168.202.21',
            'role': 'controller',
            'services': ['keystone', 'glance', 'nova', 'neutron', 'horizon']
        },
        'worker1': {
            'ip': '10.60.2.22',
            'mgmt_ip': '192.168.202.22', 
            'role': 'compute',
            'services': ['nova-compute', 'neutron-agent']
        },
        'worker2': {
            'ip': '10.60.2.23',
            'mgmt_ip': '192.168.202.23',
            'role': 'compute',
            'services': ['nova-compute', 'neutron-agent']
        },
        'worker3': {
            'ip': '10.60.2.24',
            'mgmt_ip': '192.168.202.24',
            'role': 'compute', 
            'services': ['nova-compute', 'neutron-agent']
        }
    },
    
    # URLs de servicios (headnode como controller)
    'endpoints': {
        'keystone': {
            'public': 'http://10.60.2.21:5000/v3',
            'internal': 'http://192.168.202.21:5000/v3',
            'admin': 'http://192.168.202.21:5000/v3'
        },
        'nova': {
            'public': 'http://10.60.2.21:8774/v2.1',
            'internal': 'http://192.168.202.21:8774/v2.1'
        },
        'neutron': {
            'public': 'http://10.60.2.21:9696/v2.0',
            'internal': 'http://192.168.202.21:9696/v2.0'
        },
        'glance': {
            'public': 'http://10.60.2.21:9292/v2',
            'internal': 'http://192.168.202.21:9292/v2'
        },
        'horizon': {
            'public': 'http://10.60.2.21/horizon',
            'internal': 'http://192.168.202.21/horizon'
        }
    },
    
    # Credenciales administrativas
    'admin_credentials': {
        'username': 'admin',
        'password': 'admin123',  # Cambiar por la real
        'project_name': 'admin',
        'domain_name': 'Default',
        'region_name': 'RegionOne'
    },
    
    # Configuración de red provider (según R5)
    'provider_networks': {
        'external': {
            'name': 'external',
            'physical_network': 'provider',
            'network_type': 'vlan',
            'vlan_range': '100:200'
        }
    },
    
    # Flavors estándar para el curso
    'flavors': {
        'm1.nano': {'vcpus': 1, 'ram': 64, 'disk': 1},
        'm1.micro': {'vcpus': 1, 'ram': 128, 'disk': 1}, 
        'm1.tiny': {'vcpus': 1, 'ram': 512, 'disk': 1},
        'm1.small': {'vcpus': 1, 'ram': 2048, 'disk': 20},
        'm1.medium': {'vcpus': 2, 'ram': 4096, 'disk': 40},
        'm1.large': {'vcpus': 4, 'ram': 8192, 'disk': 80}
    },
    
    # Imágenes base disponibles
    'base_images': {
        'cirros': {
            'name': 'cirros-0.5.2',
            'url': 'http://download.cirros-cloud.net/0.5.2/cirros-0.5.2-x86_64-disk.img',
            'format': 'qcow2'
        },
        'ubuntu-20.04': {
            'name': 'ubuntu-20.04-server',
            'url': 'https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img',
            'format': 'qcow2'
        }
    }
}

# Zonas de disponibilidad (para VM Placement R4)
AVAILABILITY_ZONES = {
    'zone1-openstack': {
        'name': 'zone1-openstack',
        'hosts': ['worker1', 'worker2']
    },
    'zone2-openstack': {
        'name': 'zone2-openstack', 
        'hosts': ['worker3']
    }
}