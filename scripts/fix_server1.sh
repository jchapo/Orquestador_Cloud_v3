#!/usr/bin/env python3
"""
Test básico del Linux Driver con infraestructura real PUCP
"""

import sys
import os
sys.path.append('/opt/pucp-orchestrator')

import logging
import time

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Mock del Linux Driver adaptado para PUCP real
class PUCPRealLinuxDriver:
    """Driver simplificado para testing con infraestructura real PUCP"""
    
    def __init__(self):
        # Configuración real de PUCP
        self.hypervisors = {
            'server1': {
                'uri': 'qemu+ssh://pucp-server1/system',
                'mgmt_ip': '192.168.201.1',
                'ssh_host': 'pucp-server1',
                'max_vcpus': 4,
                'max_ram': 3800,  # 3.8GB observado
                'max_disk': 50
            }
            # Solo server1 por ahora para testing inicial
        }
    
    def test_connectivity(self):
        """Test de conectividad SSH"""
        print("=== Test 1: Conectividad SSH ===")
        
        for server_name, config in self.hypervisors.items():
            try:
                import subprocess
                result = subprocess.run([
                    'ssh', '-o', 'ConnectTimeout=5', 
                    config['ssh_host'], 'hostname'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    hostname = result.stdout.strip()
                    print(f"✅ {server_name}: SSH OK (hostname: {hostname})")
                else:
                    print(f"❌ {server_name}: SSH Failed")
                    return False
                    
            except Exception as e:
                print(f"❌ {server_name}: Error - {e}")
                return False
        
        return True
    
    def test_libvirt_connection(self):
        """Test de conexión libvirt"""
        print("\n=== Test 2: Conexión libvirt ===")
        
        try:
            import libvirt
            
            for server_name, config in self.hypervisors.items():
                try:
                    # Conectar a libvirt
                    conn = libvirt.open(config['uri'])
                    if conn is None:
                        print(f"❌ {server_name}: No se pudo conectar a libvirt")
                        return False
                    
                    # Test básico
                    hostname = conn.getHostname()
                    nodeinfo = conn.getInfo()
                    
                    print(f"✅ {server_name}: libvirt OK")
                    print(f"   Hostname: {hostname}")
                    print(f"   CPU cores: {nodeinfo[2]}")
                    print(f"   Memory: {nodeinfo[1] // 1024} GB")
                    
                    # Test de dominios
                    domains = conn.listAllDomains()
                    print(f"   VMs existentes: {len(domains)}")
                    
                    conn.close()
                    
                except libvirt.libvirtError as e:
                    print(f"❌ {server_name}: libvirt Error - {e}")
                    return False
                    
        except ImportError:
            print("❌ libvirt-python no disponible")
            print("   Instalar con: pip install libvirt-python")
            return False
        
        return True
    
    def test_storage_pools(self):
        """Test de storage pools"""
        print("\n=== Test 3: Storage Pools ===")
        
        try:
            import libvirt
            
            for server_name, config in self.hypervisors.items():
                try:
                    conn = libvirt.open(config['uri'])
                    
                    # Listar storage pools
                    pools = conn.listAllStoragePools()
                    print(f"✅ {server_name}: {len(pools)} storage pools encontrados")
                    
                    for pool in pools:
                        pool_name = pool.name()
                        is_active = pool.isActive()
                        status = "activo" if is_active else "inactivo"
                        print(f"   - {pool_name}: {status}")
                        
                        if pool_name == "default" and is_active:
                            # Verificar volúmenes
                            volumes = pool.listVolumes()
                            print(f"     Imágenes: {len(volumes)}")
                            for vol in volumes[:3]:  # Mostrar solo primeras 3
                                print(f"       - {vol}")
                    
                    conn.close()
                    
                except Exception as e:
                    print(f"❌ {server_name}: Storage error - {e}")
                    return False
        
        except ImportError:
            return False
        
        return True
    
    def test_vm_creation(self):
        """Test de creación de VM básica"""
        print("\n=== Test 4: Creación de VM de Prueba ===")
        
        try:
            import libvirt
            import xml.etree.ElementTree as ET
            import uuid
            
            server_name = 'server1'
            config = self.hypervisors[server_name]
            
            print(f"Creando VM de prueba en {server_name}...")
            
            # Conectar
            conn = libvirt.open(config['uri'])
            
            # Configuración VM simple
            vm_name = f"test-pucp-vm-{int(time.time())}"
            vm_uuid = str(uuid.uuid4())
            
            # XML básico para VM de prueba
            vm_xml = f"""
            <domain type='kvm'>
                <name>{vm_name}</name>
                <uuid>{vm_uuid}</uuid>
                <memory unit='MiB'>512</memory>
                <currentMemory unit='MiB'>512</currentMemory>
                <vcpu placement='static'>1</vcpu>
                <os>
                    <type arch='x86_64' machine='pc'>hvm</type>
                    <boot dev='hd'/>
                </os>
                <features>
                    <acpi/>
                    <apic/>
                </features>
                <cpu mode='host-passthrough' check='none'/>
                <devices>
                    <emulator>/usr/bin/qemu-system-x86_64</emulator>
                    <disk type='file' device='disk'>
                        <driver name='qemu' type='qcow2'/>
                        <source file='/var/lib/libvirt/images/ubuntu-20.04-server.qcow2'/>
                        <target dev='vda' bus='virtio'/>
                    </disk>
                    <interface type='network'>
                        <source network='default'/>
                        <model type='virtio'/>
                    </interface>
                    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'/>
                </devices>
            </domain>
            """
            
            # Crear VM
            try:
                domain = conn.defineXML(vm_xml)
                print(f"✅ VM {vm_name} definida")
                
                # Arrancar VM
                domain.create()
                print(f"✅ VM {vm_name} arrancada")
                
                # Verificar estado
                time.sleep(3)
                state = domain.state()[0]
                state_names = {1: 'running', 2: 'blocked', 3: 'paused', 4: 'shutdown', 5: 'shutoff', 6: 'crashed'}
                print(f"   Estado: {state_names.get(state, 'unknown')}")
                
                # Limpiar - parar y eliminar VM
                print(f"Limpiando VM de prueba...")
                if domain.isActive():
                    domain.destroy()
                domain.undefine()
                print(f"✅ VM {vm_name} eliminada")
                
                conn.close()
                return True
                
            except Exception as e:
                print(f"❌ Error con VM: {e}")
                # Intentar limpiar
                try:
                    if 'domain' in locals():
                        if domain.isActive():
                            domain.destroy()
                        domain.undefine()
                except:
                    pass
                conn.close()
                return False
                
        except Exception as e:
            print(f"❌ Test VM creation error: {e}")
            return False
    
    def test_resources(self):
        """Test de recursos disponibles"""
        print("\n=== Test 5: Recursos Disponibles ===")
        
        try:
            import subprocess
            
            for server_name, config in self.hypervisors.items():
                print(f"📊 Recursos en {server_name}:")
                
                # CPU info
                result = subprocess.run([
                    'ssh', config['ssh_host'], 
                    'nproc; free -h | grep Mem; df -h / | tail -1'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) >= 3:
                        cpus = lines[0]
                        memory = lines[1].split()[1]
                        disk = lines[2].split()[3]
                        
                        print(f"   CPU cores: {cpus}")
                        print(f"   Memory: {memory}")
                        print(f"   Disk free: {disk}")
                        print(f"   Max VMs estimadas: {min(int(cpus), int(config['max_ram'])//512)}")
                
        except Exception as e:
            print(f"❌ Error getting resources: {e}")
            return False
        
        return True

def main():
    """Ejecutar todos los tests"""
    print("🚀 PUCP Real Infrastructure Driver Tests")
    print("=" * 50)
    
    driver = PUCPRealLinuxDriver()
    
    tests = [
        ("Conectividad SSH", driver.test_connectivity),
        ("Conexión libvirt", driver.test_libvirt_connection),
        ("Storage Pools", driver.test_storage_pools),
        ("Recursos", driver.test_resources),
        ("Creación VM", driver.test_vm_creation),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except KeyboardInterrupt:
            print(f"\n⚠️ Test interrumpido por usuario")
            break
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
        
        print("")
    
    print("=" * 50)
    print(f"📋 RESULTADO FINAL: {passed}/{total} tests pasados")
    
    if passed == total:
        print("🎉 ¡TODOS LOS TESTS PASARON!")
        print("   El driver está listo para usar con la infraestructura real")
    elif passed >= 3:
        print("⚠️  La mayoría de tests pasaron - funcionalidad básica OK")
        print("   Puedes proceder pero algunos features pueden tener problemas")
    else:
        print("❌ Demasiados tests fallaron")
        print("   Revisar configuración antes de continuar")

if __name__ == '__main__':
    main()
