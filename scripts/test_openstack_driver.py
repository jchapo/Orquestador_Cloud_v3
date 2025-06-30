#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import json
import time
from slice_service.drivers.openstack_driver import OpenStackDriver

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_openstack_connection():
    print("\n=== Prueba 1: Conexión con OpenStack ===")
    try:
        driver = OpenStackDriver()
        print("Conexión exitosa con OpenStack")
        return driver
    except Exception as e:
        print(f"Error al conectar: {e}")
        return None

def test_get_resources(driver):
    print("\n=== Prueba 2: Obtener recursos disponibles ===")
    try:
        resources = driver.get_available_resources()
        print(f"Recursos de OpenStack:")
        print(f"   Total de VCPUs: {resources['hypervisors']['vcpus_total']}")
        print(f"   VCPUs usados: {resources['hypervisors']['vcpus_used']}")
        print(f"   Total de RAM: {resources['hypervisors']['memory_total_mb']} MB")
        print(f"   RAM usada: {resources['hypervisors']['memory_used_mb']} MB")
        print(f"   VMs en ejecución: {resources['hypervisors']['running_vms']}")
        print(f"   Zonas de disponibilidad: {resources['availability_zones']}")
        
        if 'hypervisor_details' in resources:
            print("\n   Detalles de los Hypervisores:")
            for host, details in resources['hypervisor_details'].items():
                print(f"   - {host}: {details['vcpus']} vCPUs, "
                      f"{details['memory_mb']} MB de RAM, "
                      f"Estado: {details['state']}")
        
        return True
    except Exception as e:
        print(f"Error al obtener los recursos: {e}")
        return False

def test_flavors_and_images(driver):
    print("\n=== Prueba 3: Flavors e Imágenes ===")
    try:
        flavors = driver.get_supported_flavors()
        print(f"Flavors disponibles ({len(flavors)}):")
        for flavor in flavors[:5]:  # Mostrar los primeros 5
            print(f"   - {flavor['name']}: {flavor['vcpus']} vCPUs, "
                  f"{flavor['ram']} MB de RAM, {flavor['disk']} GB de disco")
        
        images = driver.get_supported_images()
        print(f"\nImágenes disponibles ({len(images)}):")
        for image in images[:5]:  # Mostrar las primeras 5
            print(f"   - {image['name']} (ID: {image['id'][:8]}...)")
        
        return True
    except Exception as e:
        print(f"Error al listar flavors/imágenes: {e}")
        return False

def test_create_vm(driver):
    print("\n=== Prueba 4: Crear VM de prueba ===")
    
    vm_config = {
        'name': f'test-openstack-vm-{int(time.time())}',
        'flavor': 'small',
        'image': 'cirros-0.5.2',
        'network': {
            'name': 'test-network',
            'cidr': '192.168.100.0/24'
        }
    }
    
    placement = {
        'zone': 'nova'
    }
    
    try:
        print(f"Creando VM: {vm_config['name']}...")
        result = driver.create_vm(vm_config, placement)
        print(f"VM creada exitosamente:")
        print(f"   ID: {result['id']}")
        print(f"   Nombre: {result['name']}")
        print(f"   Estado: {result['status']}")
        print(f"   IP: {result.get('ip_address', 'Pendiente')}")
        print(f"   AZ: {result.get('availability_zone', 'Desconocido')}")
        
        return result
    except Exception as e:
        print(f"Error al crear la VM: {e}")
        return None

def test_delete_vm(driver, vm_info):
    print("\n=== Prueba 5: Eliminar VM de prueba ===")
    
    if not vm_info:
        print("No hay VM para eliminar (la creación falló)")
        return False
    
    try:
        print(f"Eliminando la VM {vm_info['id']}...")
        success = driver.delete_vm(vm_info['id'])
        if success:
            print("VM eliminada exitosamente")
            return True
        else:
            print("Error al eliminar la VM")
            return False
    except Exception as e:
        print(f"Error al eliminar la VM: {e}")
        return False

def test_slice_deployment(driver):
    print("\n=== Prueba 6: Desplegar un slice completo ===")
    
    slice_config = {
        'id': f'test-slice-{int(time.time())}',
        'name': 'test-openstack-slice',
        'networks': [
            {
                'name': 'slice-net-1',
                'cidr': '192.168.200.0/24'
            }
        ],
        'vms': [
            {
                'name': 'slice-vm-1',
                'flavor': 'small',
                'image': 'cirros-0.5.2',
                'networks': ['slice-net-1']
            },
            {
                'name': 'slice-vm-2',
                'flavor': 'small',
                'image': 'cirros-0.5.2',
                'networks': ['slice-net-1']
            }
        ],
        'security_rules': [
            {
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 80,
                'port_range_max': 80,
                'remote_ip_prefix': '0.0.0.0/0'
            }
        ]
    }
    
    placement = {
        'slice-vm-1': {'zone': 'nova'},
        'slice-vm-2': {'zone': 'nova'}
    }
    
    try:
        print(f"Desplegando el slice con {len(slice_config['vms'])} VMs...")
        result = driver.deploy_slice(slice_config, placement)
        
        if result['status'] == 'deployed':
            print(f"Slice desplegado exitosamente:")
            print(f"   Slice ID: {result['slice_id']}")
            print(f"   VMs desplegadas: {len(result['deployed_vms'])}")
            print(f"   Redes creadas: {len(result['created_networks'])}")
            
            for vm in result['deployed_vms']:
                print(f"   - {vm['name']}: {vm['status']} "
                      f"(IP: {vm.get('ip_address', 'Pendiente')})")
            
            return result
        else:
            print(f"Error al desplegar el slice:")
            for error in result.get('errors', []):
                print(f"   - {error}")
            return None
            
    except Exception as e:
        print(f"Error al desplegar el slice: {e}")
        return None

def test_delete_slice(driver, slice_result):
    print("\n=== Prueba 7: Eliminar Slice de prueba ===")
    
    if not slice_result:
        print("No hay slice para eliminar (el despliegue falló)")
        return False
    
    try:
        print(f"Eliminando el slice {slice_result['slice_id']}...")
        
        slice_vms = [{'external_id': vm['id'], 'name': vm['name']} 
                     for vm in slice_result['deployed_vms']]
        slice_networks = [{'external_id': net['id'], 'name': net['name']} 
                         for net in slice_result['created_networks']]
        
        success = driver.delete_slice(
            slice_result['slice_id'],
            slice_vms,
            slice_networks
        )
        
        if success:
            print("Slice eliminado exitosamente")
            return True
        else:
            print("Error al eliminar el slice")
            return False
            
    except Exception as e:
        print(f"Error al eliminar el slice: {e}")
        return False

def main():
    print("Pruebas del Controlador OpenStack PUCP")
    print("===================================")
    
    driver = test_openstack_connection()
    if not driver:
        print("\nNo se puede continuar sin la conexión")
        return
    
    test_get_resources(driver)
    test_flavors_and_images(driver)
    
    print("\n--- Prueba del ciclo de vida de una VM ---")
    vm_info = test_create_vm(driver)
    if vm_info:
        input("\nPresione Enter para eliminar la VM de prueba...")
        test_delete_vm(driver, vm_info)
    
    print("\n--- Prueba del ciclo de vida del Slice ---")
    slice_result = test_slice_deployment(driver)
    if slice_result:
        input("\nPresione Enter para eliminar el slice de prueba...")
        test_delete_slice(driver, slice_result)
    
    print("\nTodas las pruebas completadas con éxito")

if __name__ == '__main__':
    main()