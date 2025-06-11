#!/usr/bin/env python3
"""
Test del Linux Driver para PUCP Cloud Orchestrator
"""

import sys
import os
sys.path.append('/opt/pucp-orchestrator')

from slice_service.drivers.linux_driver import LinuxClusterDriver
import json
import time
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_basic_connectivity():
    """Test básico de conectividad"""
    print("=== Test 1: Conectividad Básica ===")
    
    driver = LinuxClusterDriver()
    
    # Test de conexión a cada servidor
    for server_name in driver.hypervisors.keys():
        try:
            conn = driver.get_connection(server_name)
            if conn and conn.isAlive():
                print(f"✅ {server_name}: Conectado")
                
                # Info básica del host
                host_info = conn.getInfo()
                print(f"   CPU cores: {host_info[2]}")
                print(f"   Memoria: {host_info[1] // 1024} GB")
                
            else:
                print(f"❌ {server_name}: Conexión falló")
                
        except Exception as e:
            print(f"❌ {server_name}: Error - {e}")
    
    driver.close_connections()

def test_vm_creation():
    """Test de creación de VM"""
    print("\n=== Test 2: Creación de VM ===")
    
    driver = LinuxClusterDriver()
    
    # Configuración de VM de prueba
    vm_config = {
        'name': 'test-vm-pucp',
        'cpu': 1,
        'ram': 1024,  # MB
        'disk': 10,   # GB
        'image': 'ubuntu-20.04'
    }
    
    server_name = 'server1'  # Usar primer servidor para prueba
    
    try:
        print(f"Creando VM {vm_config['name']} en {server_name}...")
        
        result = driver.create_vm(vm_config, server_name, slice_id='test-slice')
        
        print("✅ VM creada exitosamente!")
        print(f"   VM ID: {result['vm_id']}")
        print(f"   Nombre: {result['name']}")
        print(f"   Estado: {result['status']}")
        print(f"   Servidor: {result['server']}")
        if result.get('ip_address'):
            print(f"   IP: {result['ip_address']}")
        if result.get('console_url'):
            print(f"   Consola: {result['console_url']}")
        
        # Esperar un poco y verificar estado
        print("\nEsperando 10 segundos y verificando estado...")
        time.sleep(10)
        
        status = driver.get_vm_status(vm_config['name'], server_name)
        print(f"Estado actual: {status['status']}")
        
        # Cleanup: eliminar VM de prueba
        print(f"\nEliminando VM de prueba...")
        if driver.delete_vm(vm_config['name'], server_name):
            print("✅ VM eliminada correctamente")
        else:
            print("❌ Error eliminando VM")
            
    except Exception as e:
        print(f"❌ Error creando VM: {e}")
        
        # Intentar cleanup en caso de error
        try:
            driver.delete_vm(vm_config['name'], server_name)
        except:
            pass
    
    driver.close_connections()

def test_resource_monitoring():
    """Test de monitoreo de recursos"""
    print("\n=== Test 3: Monitoreo de Recursos ===")
    
    driver = LinuxClusterDriver()
    
    try:
        resources = driver.get_server_resources()
        
        print("Recursos del cluster:")
        for resource in resources:
            print(f"\n🖥️  {resource['hostname']} ({resource['ip']})")
            print(f"   Estado: {resource['status']}")
            print(f"   CPU: {resource['used_vcpus']}/{resource['total_vcpus']} "
                  f"({resource['cpu_utilization']:.1f}%)")
            print(f"   RAM: {resource['used_ram']}/{resource['total_ram']} MB "
                  f"({resource['ram_utilization']:.1f}%)")
            print(f"   VMs activas: {resource['active_vms']}/{resource['total_vms']}")
            
    except Exception as e:
        print(f"❌ Error obteniendo recursos: {e}")
    
    driver.close_connections()

def test_slice_deployment():
    """Test de deployment de slice completo"""
    print("\n=== Test 4: Deployment de Slice ===")
    
    driver = LinuxClusterDriver()
    
    # Configuración de slice de prueba (topología lineal simple)
    slice_config = {
        'id': 'test-slice-linear',
        'name': 'Test Linear Topology',
        'infrastructure': 'linux',
        'nodes': [
            {
                'name': 'vm1',
                'image': 'ubuntu-20.04',
                'flavor': 'small',
                'cpu': 1,
                'ram': 1024,
                'disk': 10
            },
            {
                'name': 'vm2',
                'image': 'ubuntu-20.04', 
                'flavor': 'small',
                'cpu': 1,
                'ram': 1024,
                'disk': 10
            }
        ],
        'networks': [
            {
                'name': 'test-network',
                'cidr': '192.168.100.0/24',
                'gateway': '192.168.100.1'
            }
        ]
    }
    
    # Placement manual para test
    placement = {
        'vm1': {'hostname': 'server1', 'server_id': 'server1'},
        'vm2': {'hostname': 'server2', 'server_id': 'server2'}
    }
    
    try:
        print("Desplegando slice de prueba...")
        print(f"VMs: {len(slice_config['nodes'])}")
        print(f"Redes: {len(slice_config['networks'])}")
        
        result = driver.deploy_slice(slice_config, placement)
        
        if result['status'] == 'success':
            print("✅ Slice desplegado exitosamente!")
            print(f"   VMs desplegadas: {len(result['deployed_vms'])}")
            print(f"   Redes creadas: {len(result['created_networks'])}")
            
            # Mostrar detalles de VMs
            for vm in result['deployed_vms']:
                print(f"   • {vm['name']}: {vm['status']} en {vm['server']}")
        
        else:
            print(f"❌ Deployment falló: {result.get('error')}")
            if result.get('errors'):
                for error in result['errors']:
                    print(f"   - {error}")
        
        # Cleanup: destruir slice de prueba
        print("\nLimpiando slice de prueba...")
        if result['status'] == 'success':
            vm_list = result['deployed_vms']
            cleanup_result = driver.destroy_slice(slice_config['id'], vm_list)
            
            if cleanup_result['status'] == 'success':
                print("✅ Slice eliminado correctamente")
            else:
                print(f"❌ Error eliminando slice: {cleanup_result.get('error')}")
                
    except Exception as e:
        print(f"❌ Error en deployment: {e}")
        import traceback
        traceback.print_exc()
    
    driver.close_connections()

def test_vm_listing():
    """Test de listado de VMs"""
    print("\n=== Test 5: Listado de VMs ===")
    
    driver = LinuxClusterDriver()
    
    try:
        vms = driver.list_vms()
        
        if vms:
            print(f"VMs encontradas: {len(vms)}")
            for vm in vms:
                print(f"   • {vm['name']}: {vm['status']} en {vm['server']}")
                if vm.get('ip_address'):
                    print(f"     IP: {vm['ip_address']}")
        else:
            print("No hay VMs en el cluster")
            
    except Exception as e:
        print(f"❌ Error listando VMs: {e}")
    
    driver.close_connections()

def main():
    """Ejecutar todos los tests"""
    print("🚀 PUCP Cloud Orchestrator - Linux Driver Tests")
    print("=" * 50)
    
    try:
        test_basic_connectivity()
        test_resource_monitoring()
        test_vm_listing()
        test_vm_creation()
        test_slice_deployment()
        
        print("\n" + "=" * 50)
        print("✅ Tests completados!")
        print("\nSi todos los tests pasaron, el driver está listo para usar.")
        
    except KeyboardInterrupt:
        print("\n⚠️ Tests interrumpidos por el usuario")
    except Exception as e:
        print(f"\n❌ Error crítico en tests: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()