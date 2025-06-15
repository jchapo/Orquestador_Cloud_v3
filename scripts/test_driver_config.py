#!/usr/bin/env python3
"""
Verificación de configuración del Linux Driver
"""

import sys
sys.path.append('/opt/pucp-orchestrator/slice_service')

from drivers.linux_driver import LinuxClusterDriver
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_driver_config():
    """Prueba la configuración del driver"""
    
    print("🔍 Verificando configuración del Linux Driver")
    print("=" * 50)
    
    try:
        driver = LinuxClusterDriver()
        
        print(f"✅ Driver inicializado: {driver.driver_name}")
        print(f"📡 Bridge OVS: {driver.ovs_bridge}")
        print(f"🌐 Rango de red: {driver.network_range}")
        
        print("\n🖥️ Hypervisors configurados:")
        for server_name, config in driver.hypervisors.items():
            print(f"   • {server_name}: {config['uri']}")
        
        print("\n💿 Imágenes disponibles:")
        for image_name, config in driver.available_images.items():
            print(f"   • {image_name}: {config['path']}")
        
        # Probar conectividad
        print("\n🔗 Probando conectividad SSH...")
        for server_name in driver.hypervisors.keys():
            try:
                conn = driver.get_connection(server_name)
                if conn and conn.isAlive():
                    print(f"   ✅ {server_name}: Conectado")
                    conn.close()
                else:
                    print(f"   ❌ {server_name}: No se pudo conectar")
            except Exception as e:
                print(f"   ❌ {server_name}: Error - {e}")
        
        print("\n✅ Verificación completa")
        return True
        
    except Exception as e:
        print(f"\n❌ Error en verificación: {e}")
        return False

def test_vm_config():
    """Prueba configuración de VM"""
    
    print("\n🖥️ Probando configuración de VM...")
    
    driver = LinuxClusterDriver()
    
    test_vm_config = {
        'name': 'test-vm',
        'cpu': 1,
        'ram': 1024,
        'disk': 10,
        'image': 'ubuntu-20.04'
    }
    
    try:
        # Probar validación
        driver._validate_vm_config(test_vm_config, 'server1')
        print("✅ Configuración de VM válida")
        
        # Probar generación de MAC
        mac = driver._generate_mac_address('test-vm', 'server1')
        print(f"✅ MAC generada: {mac}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en configuración de VM: {e}")
        return False

if __name__ == '__main__':
    success = test_driver_config() and test_vm_config()
    
    if success:
        print("\n🎉 Todas las verificaciones pasaron!")
        sys.exit(0)
    else:
        print("\n💥 Algunas verificaciones fallaron")
        sys.exit(1)
