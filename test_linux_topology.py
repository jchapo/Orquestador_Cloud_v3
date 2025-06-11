#!/usr/bin/env python3
# test_linux_topology.py

from slice_service.drivers.linux_driver import LinuxClusterDriver
import json

def create_simple_topology():
    """Crea una topología lineal simple en el cluster Linux"""
    
    driver = LinuxClusterDriver()
    
    # Definir topología de 3 VMs en línea
    topology = {
        'name': 'test-linear-topology',
        'vms': [
            {
                'name': 'vm1',
                'cpu': 1,
                'ram': 1024,
                'disk': 10,
                'image': 'ubuntu-20.04',
                'networks': ['net1']
            },
            {
                'name': 'vm2', 
                'cpu': 1,
                'ram': 1024,
                'disk': 10,
                'image': 'ubuntu-20.04',
                'networks': ['net1', 'net2']
            },
            {
                'name': 'vm3',
                'cpu': 1,
                'ram': 1024, 
                'disk': 10,
                'image': 'ubuntu-20.04',
                'networks': ['net2']
            }
        ],
        'networks': [
            {'name': 'net1', 'cidr': '192.168.100.0/24'},
            {'name': 'net2', 'cidr': '192.168.101.0/24'}
        ]
    }
    
    # Placement manual para empezar
    placement = {
        'vm1': 'server1',
        'vm2': 'server2', 
        'vm3': 'server3'
    }
    
    # Crear VMs
    created_vms = []
    for vm in topology['vms']:
        try:
            result = driver.create_vm(vm, placement[vm['name']])
            created_vms.append(result)
            print(f"✓ VM {vm['name']} creada en {placement[vm['name']]}")
        except Exception as e:
            print(f"✗ Error creando {vm['name']}: {e}")
    
    return created_vms

if __name__ == "__main__":
    create_simple_topology()
