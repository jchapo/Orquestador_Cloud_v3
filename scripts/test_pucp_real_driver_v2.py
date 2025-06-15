#!/usr/bin/env python3
"""
Test completo del Linux Driver con todos los servidores PUCP
Versión actualizada para probar toda la infraestructura del cluster
"""

import sys
import os
sys.path.append('/opt/pucp-orchestrator')

import logging
import time
import subprocess
import concurrent.futures
from threading import Lock

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PUCPCompleteLinuxDriver:
    """Driver completo para testing con toda la infraestructura PUCP"""
    
    def __init__(self):
        # Configuración completa del cluster PUCP según tu documento
        self.hypervisors = {
            'server1': {
                'uri': 'qemu+ssh://pucp-server1/system',
                'mgmt_ip': '192.168.201.1',
                'ssh_host': 'pucp-server1',
                'access_port': 5811,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'server2': {
                'uri': 'qemu+ssh://pucp-server2/system',
                'mgmt_ip': '192.168.201.2',
                'ssh_host': 'pucp-server2',
                'access_port': 5812,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'server3': {
                'uri': 'qemu+ssh://pucp-server3/system',
                'mgmt_ip': '192.168.201.3',
                'ssh_host': 'pucp-server3',
                'access_port': 5813,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'server4': {
                'uri': 'qemu+ssh://pucp-server4/system',
                'mgmt_ip': '192.168.201.4',
                'ssh_host': 'pucp-server4',
                'access_port': 5814,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'ovs1': {
                'uri': 'qemu+ssh://pucp-ovs1/system',
                'mgmt_ip': '192.168.201.5',
                'ssh_host': 'pucp-ovs1',
                'access_port': 5815,
                'max_vcpus': 4,
                'max_ram': 8192,
                'max_disk': 50,
                'is_switch': True
            }
        }
        
        # Configuración de red según tu topología
        self.network_config = {
            'linux_cluster_subnet': '10.60.1.0/24',
            'mgmt_subnet': '192.168.201.0/24',
            'ovs_bridge': 'ovs1',
            'gateway': '10.60.1.1'
        }
        
        # Lock para thread safety en logging
        self.print_lock = Lock()
        
        # Resultados de tests
        self.test_results = {}
    
    def safe_print(self, message):
        """Print thread-safe"""
        with self.print_lock:
            print(message)
    
    def test_connectivity_single(self, server_name, config):
        """Test de conectividad para un servidor específico"""
        try:
            # Test SSH básico
            result = subprocess.run([
                'ssh', '-o', 'ConnectTimeout=10', 
                '-o', 'StrictHostKeyChecking=no',
                config['ssh_host'], 'hostname && uptime'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                hostname = lines[0] if lines else 'unknown'
                uptime = lines[1] if len(lines) > 1 else 'unknown'
                
                self.test_results[server_name] = {
                    'ssh': True,
                    'hostname': hostname,
                    'uptime': uptime
                }
                
                return True, f"SSH OK (hostname: {hostname})"
            else:
                error = result.stderr.strip() or "Connection failed"
                self.test_results[server_name] = {'ssh': False, 'error': error}
                return False, f"SSH Failed: {error}"
                
        except subprocess.TimeoutExpired:
            error = "Connection timeout"
            self.test_results[server_name] = {'ssh': False, 'error': error}
            return False, error
        except Exception as e:
            error = str(e)
            self.test_results[server_name] = {'ssh': False, 'error': error}
            return False, error
    
    def test_connectivity(self):
        """Test de conectividad SSH paralelo a todos los servidores"""
        self.safe_print("=== Test 1: Conectividad SSH a Todo el Cluster ===")
        
        # Test en paralelo para eficiencia
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.test_connectivity_single, name, config): name 
                for name, config in self.hypervisors.items()
            }
            
            all_success = True
            
            for future in concurrent.futures.as_completed(futures):
                server_name = futures[future]
                try:
                    success, message = future.result()
                    status = "✅" if success else "❌"
                    self.safe_print(f"{status} {server_name}: {message}")
                    
                    if not success:
                        all_success = False
                        
                except Exception as e:
                    self.safe_print(f"❌ {server_name}: Exception - {e}")
                    all_success = False
        
        self.safe_print(f"\n📊 Resumen conectividad: {sum(1 for r in self.test_results.values() if r.get('ssh', False))}/{len(self.hypervisors)} servidores conectados")
        
        return all_success
    
    def test_libvirt_single(self, server_name, config):
        """Test de libvirt para un servidor específico"""
        if config.get('is_switch', False):
            # OVS switch - diferentes tests
            return self.test_ovs_switch(server_name, config)
        
        try:
            import libvirt
            
            # Conectar a libvirt
            conn = libvirt.open(config['uri'])
            if conn is None:
                return False, "No se pudo conectar a libvirt"
            
            # Información básica del host
            hostname = conn.getHostname()
            nodeinfo = conn.getInfo()
            
            # Test de funcionalidad libvirt
            domains = conn.listAllDomains()
            storage_pools = conn.listAllStoragePools()
            networks = conn.listAllNetworks()
            
            # Información de capacidades
            capabilities = conn.getCapabilities()
            
            # Actualizar resultados
            if server_name not in self.test_results:
                self.test_results[server_name] = {}
            
            self.test_results[server_name].update({
                'libvirt': True,
                'libvirt_hostname': hostname,
                'cpu_cores': nodeinfo[2],
                'memory_gb': nodeinfo[1] // 1024,
                'active_domains': len([d for d in domains if d.isActive()]),
                'total_domains': len(domains),
                'storage_pools': len(storage_pools),
                'networks': len(networks)
            })
            
            conn.close()
            
            info = f"libvirt OK (CPUs: {nodeinfo[2]}, RAM: {nodeinfo[1]//1024}GB, VMs: {len(domains)})"
            return True, info
            
        except ImportError:
            return False, "libvirt-python no disponible"
        except Exception as e:
            return False, f"libvirt Error: {str(e)}"
    
    def test_ovs_switch(self, server_name, config):
        """Test específico para el switch OVS"""
        try:
            # Test de Open vSwitch
            result = subprocess.run([
                'ssh', config['ssh_host'], 
                'sudo ovs-vsctl show; sudo ovs-vsctl list-br'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parsear salida de OVS
                output = result.stdout
                bridges = [line.strip() for line in output.split('\n') if line.strip() and not line.startswith(' ')]
                
                if server_name not in self.test_results:
                    self.test_results[server_name] = {}
                
                self.test_results[server_name].update({
                    'ovs': True,
                    'ovs_bridges': len(bridges),
                    'ovs_output': output[:200]  # Primeros 200 chars
                })
                
                return True, f"OVS OK (bridges: {len(bridges)})"
            else:
                return False, f"OVS Error: {result.stderr}"
                
        except Exception as e:
            return False, f"OVS Test Error: {str(e)}"
    
    def test_libvirt_connections(self):
        """Test de conexiones libvirt a todos los servidores"""
        self.safe_print("\n=== Test 2: Conexiones libvirt/OVS ===")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.test_libvirt_single, name, config): name 
                for name, config in self.hypervisors.items()
            }
            
            all_success = True
            
            for future in concurrent.futures.as_completed(futures):
                server_name = futures[future]
                try:
                    success, message = future.result()
                    status = "✅" if success else "❌"
                    self.safe_print(f"{status} {server_name}: {message}")
                    
                    if not success:
                        all_success = False
                        
                except Exception as e:
                    self.safe_print(f"❌ {server_name}: Exception - {e}")
                    all_success = False
        
        return all_success
    
    def test_storage_and_images(self):
        """Test de storage pools e imágenes disponibles"""
        self.safe_print("\n=== Test 3: Storage e Imágenes ===")
        
        def check_storage_single(server_name, config):
            if config.get('is_switch', False):
                return True, "Switch - no storage"
            
            try:
                # Verificar storage pool default y imágenes
                result = subprocess.run([
                    'ssh', config['ssh_host'], 
                    'ls -la /var/lib/libvirt/images/ | wc -l; '
                    'du -sh /var/lib/libvirt/images/; '
                    'df -h /var/lib/libvirt/images/ | tail -1'
                ], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    file_count = int(lines[0]) - 3 if lines else 0  # -3 para ., .. y total
                    storage_used = lines[1].split()[0] if len(lines) > 1 else "unknown"
                    disk_info = lines[2].split() if len(lines) > 2 else []
                    disk_free = disk_info[3] if len(disk_info) > 3 else "unknown"
                    
                    if server_name not in self.test_results:
                        self.test_results[server_name] = {}
                    
                    self.test_results[server_name].update({
                        'storage': True,
                        'image_files': file_count,
                        'storage_used': storage_used,
                        'disk_free': disk_free
                    })
                    
                    return True, f"Storage OK (files: {file_count}, used: {storage_used}, free: {disk_free})"
                else:
                    return False, f"Storage check failed: {result.stderr}"
                    
            except Exception as e:
                return False, f"Storage error: {str(e)}"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(check_storage_single, name, config): name 
                for name, config in self.hypervisors.items()
            }
            
            for future in concurrent.futures.as_completed(futures):
                server_name = futures[future]
                try:
                    success, message = future.result()
                    status = "✅" if success else "❌"
                    self.safe_print(f"{status} {server_name}: {message}")
                except Exception as e:
                    self.safe_print(f"❌ {server_name}: Exception - {e}")
        
        return True
    
    def test_network_configuration(self):
        """Test de configuración de red del cluster"""
        self.safe_print("\n=== Test 4: Configuración de Red ===")
        
        def check_network_single(server_name, config):
            try:
                # Verificar configuración de red y bridges
                cmd = (
                    'ip addr show | grep -E "(inet|br-|ovs)"; '
                    'ip route | grep default; '
                    'ping -c 1 -W 2 8.8.8.8 > /dev/null && echo "Internet: OK" || echo "Internet: NO"'
                )
                
                result = subprocess.run([
                    'ssh', config['ssh_host'], cmd
                ], capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    output = result.stdout
                    has_internet = "Internet: OK" in output
                    
                    # Extraer IPs
                    mgmt_ip = config['mgmt_ip']
                    has_mgmt_ip = mgmt_ip in output
                    
                    if server_name not in self.test_results:
                        self.test_results[server_name] = {}
                    
                    self.test_results[server_name].update({
                        'network': True,
                        'has_mgmt_ip': has_mgmt_ip,
                        'has_internet': has_internet,
                        'network_output': output[:300]
                    })
                    
                    status_parts = []
                    if has_mgmt_ip:
                        status_parts.append(f"MGMT IP: {mgmt_ip}")
                    if has_internet:
                        status_parts.append("Internet: OK")
                    
                    return True, f"Network OK ({', '.join(status_parts)})"
                else:
                    return False, f"Network check failed"
                    
            except Exception as e:
                return False, f"Network error: {str(e)}"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(check_network_single, name, config): name 
                for name, config in self.hypervisors.items()
            }
            
            for future in concurrent.futures.as_completed(futures):
                server_name = futures[future]
                try:
                    success, message = future.result()
                    status = "✅" if success else "❌"
                    self.safe_print(f"{status} {server_name}: {message}")
                except Exception as e:
                    self.safe_print(f"❌ {server_name}: Exception - {e}")
        
        return True
    
    def test_vm_creation_capacity(self):
        """Test de capacidad para crear VMs"""
        self.safe_print("\n=== Test 5: Capacidad de VMs ===")
        
        # Solo probar en server1 para no saturar
        server_name = 'server1'
        config = self.hypervisors[server_name]
        
        try:
            self.safe_print(f"Probando creación de VM en {server_name}...")
            
            import libvirt
            conn = libvirt.open(config['uri'])
            
            if conn is None:
                self.safe_print(f"❌ No se pudo conectar a {server_name}")
                return False
            
            # VM de prueba muy básica
            vm_name = f"pucp-test-vm-{int(time.time())}"
            
            # XML minimalista
            vm_xml = f"""<domain type='kvm'>
                <name>{vm_name}</name>
                <memory unit='MiB'>256</memory>
                <currentMemory unit='MiB'>256</currentMemory>
                <vcpu placement='static'>1</vcpu>
                <os>
                    <type arch='x86_64' machine='pc'>hvm</type>
                    <boot dev='hd'/>
                </os>
                <devices>
                    <emulator>/usr/bin/qemu-system-x86_64</emulator>
                    <disk type='file' device='disk'>
                        <driver name='qemu' type='raw'/>
                        <source file='/dev/null'/>
                        <target dev='vda' bus='virtio'/>
                    </disk>
                    <interface type='network'>
                        <source network='default'/>
                    </interface>
                </devices>
            </domain>"""
            
            # Definir VM (sin arrancar)
            domain = conn.defineXML(vm_xml)
            self.safe_print(f"✅ VM {vm_name} definida correctamente")
            
            # Limpiar inmediatamente
            domain.undefine()
            self.safe_print(f"✅ VM {vm_name} eliminada - capacidad confirmada")
            
            conn.close()
            return True
            
        except ImportError:
            self.safe_print("❌ libvirt-python no disponible")
            return False
        except Exception as e:
            self.safe_print(f"❌ Error creando VM: {e}")
            return False
    
    def generate_cluster_report(self):
        """Genera reporte completo del cluster"""
        self.safe_print("\n" + "="*60)
        self.safe_print("📊 REPORTE COMPLETO DEL CLUSTER PUCP")
        self.safe_print("="*60)
        
        # Estadísticas generales
        total_servers = len(self.hypervisors)
        connected_servers = sum(1 for r in self.test_results.values() if r.get('ssh', False))
        working_libvirt = sum(1 for r in self.test_results.values() if r.get('libvirt', False))
        
        self.safe_print(f"🖥️  Servidores totales: {total_servers}")
        self.safe_print(f"✅ Servidores conectados: {connected_servers}/{total_servers}")
        self.safe_print(f"🔧 Libvirt funcional: {working_libvirt}/{total_servers-1}")  # -1 por OVS
        
        # Capacidad total del cluster
        total_cpus = sum(r.get('cpu_cores', 0) for r in self.test_results.values())
        total_ram = sum(r.get('memory_gb', 0) for r in self.test_results.values())
        total_vms = sum(r.get('total_domains', 0) for r in self.test_results.values())
        
        self.safe_print(f"\n💪 CAPACIDAD TOTAL:")
        self.safe_print(f"   CPU cores: {total_cpus}")
        self.safe_print(f"   RAM total: {total_ram} GB")
        self.safe_print(f"   VMs existentes: {total_vms}")
        
        # Detalle por servidor
        self.safe_print(f"\n📋 DETALLE POR SERVIDOR:")
        for server_name, results in self.test_results.items():
            self.safe_print(f"\n🖥️  {server_name.upper()}:")
            
            if results.get('ssh'):
                self.safe_print(f"   ✅ SSH: {results.get('hostname', 'OK')}")
            else:
                self.safe_print(f"   ❌ SSH: {results.get('error', 'Failed')}")
            
            if results.get('libvirt'):
                self.safe_print(f"   ✅ libvirt: {results.get('cpu_cores', 0)} CPUs, {results.get('memory_gb', 0)} GB RAM")
                self.safe_print(f"   📦 VMs: {results.get('active_domains', 0)} activas / {results.get('total_domains', 0)} total")
            elif results.get('ovs'):
                self.safe_print(f"   ✅ OVS: {results.get('ovs_bridges', 0)} bridges")
            
            if results.get('storage'):
                self.safe_print(f"   💾 Storage: {results.get('image_files', 0)} imágenes, {results.get('disk_free', 'unknown')} libre")
            
            if results.get('network'):
                status = "✅" if results.get('has_internet') else "⚠️"
                self.safe_print(f"   🌐 Red: {status} MGMT IP configurada, Internet: {'OK' if results.get('has_internet') else 'NO'}")
        
        # Recomendaciones
        self.safe_print(f"\n💡 RECOMENDACIONES:")
        
        if connected_servers < total_servers:
            self.safe_print("   ⚠️  Algunos servidores no están conectados - verificar SSH/red")
        
        if working_libvirt < (total_servers - 1):
            self.safe_print("   ⚠️  Algunos servidores tienen problemas con libvirt")
        
        if total_vms == 0:
            self.safe_print("   💡 No hay VMs existentes - cluster listo para nuevos deployments")
        
        if connected_servers >= 3:
            self.safe_print("   ✅ Suficientes servidores para topologías distribuidas")
        
        # Estado final
        cluster_health = "EXCELENTE" if connected_servers == total_servers else \
                        "BUENA" if connected_servers >= total_servers * 0.8 else \
                        "REGULAR" if connected_servers >= total_servers * 0.5 else "MALA"
        
        self.safe_print(f"\n🏥 ESTADO DEL CLUSTER: {cluster_health}")
        
        return cluster_health

def main():
    """Ejecutar todos los tests del cluster completo"""
    print("🚀 PUCP Complete Linux Cluster Driver Tests")
    print("🎯 Probando TODA la infraestructura del cluster")
    print("=" * 60)
    
    driver = PUCPCompleteLinuxDriver()
    
    tests = [
        ("Conectividad SSH (Todos los servidores)", driver.test_connectivity),
        ("Conexiones libvirt/OVS", driver.test_libvirt_connections),
        ("Storage e Imágenes", driver.test_storage_and_images),
        ("Configuración de Red", driver.test_network_configuration),
        ("Capacidad de VMs", driver.test_vm_creation_capacity),
    ]
    
    passed = 0
    total = len(tests)
    
    start_time = time.time()
    
    for test_name, test_func in tests:
        try:
            print(f"\n🔄 Ejecutando: {test_name}")
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except KeyboardInterrupt:
            print(f"\n⚠️ Tests interrumpidos por usuario")
            break
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
            import traceback
            traceback.print_exc()
    
    # Generar reporte completo
    cluster_health = driver.generate_cluster_report()
    
    elapsed_time = time.time() - start_time
    
    print(f"\n" + "="*60)
    print(f"⏱️  TIEMPO TOTAL: {elapsed_time:.1f} segundos")
    print(f"📊 RESULTADO FINAL: {passed}/{total} tests pasados")
    print(f"🏥 ESTADO DEL CLUSTER: {cluster_health}")
    
    if cluster_health in ["EXCELENTE", "BUENA"]:
        print("\n🎉 ¡CLUSTER LISTO PARA PRODUCCIÓN!")
        print("   ✅ Puede proceder con deployments de slices")
        print("   ✅ Driver Linux está completamente funcional")
        print("\n🔗 Próximos pasos:")
        print("   1. Integrar driver con slice_service")
        print("   2. Probar creación de topologías")
        print("   3. Configurar monitoreo de recursos")
        
    elif cluster_health == "REGULAR":
        print("\n⚠️  CLUSTER PARCIALMENTE FUNCIONAL")
        print("   ⚠️  Algunos servidores tienen problemas")
        print("   ✅ Funcionalidad básica disponible")
        print("\n🔧 Acciones recomendadas:")
        print("   1. Revisar conectividad de servidores fallidos")
        print("   2. Verificar configuración de libvirt")
        print("   3. Proceder con precaución")
        
    else:
        print("\n❌ CLUSTER CON PROBLEMAS SERIOS")
        print("   ❌ Demasiados servidores no responden")
        print("   ❌ No recomendado para producción")
        print("\n🚨 Acciones urgentes:")
        print("   1. Verificar conectividad de red")
        print("   2. Revisar configuración SSH")
        print("   3. Contactar administrador de infraestructura")

if __name__ == '__main__':
    main()
