#!/usr/bin/env python3
"""
Script para detectar recursos reales de los servidores PUCP
"""
import subprocess
import json
import re
from typing import Dict

def get_server_real_resources(server_name: str) -> Dict:
    """Obtiene recursos reales de un servidor via SSH"""
    
    try:
        # Comando simplificado que devuelve valores separados por comas
        ssh_cmd = f'''ssh -o StrictHostKeyChecking=no ubuntu@{server_name} '
            # Get basic info
            CPU_CORES=$(nproc)
            CPU_THREADS=$(lscpu | grep "Thread(s) per core" | grep -o "[0-9]\\+")
            CPU_SOCKETS=$(lscpu | grep "Socket(s)" | grep -o "[0-9]\\+")
            TOTAL_VCPUS=$((CPU_CORES * CPU_THREADS))
            
            # Memory in MB
            TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | grep -o "[0-9]\\+")
            TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
            AVAILABLE_RAM_MB=$((TOTAL_RAM_MB - 512))
            
            # Disk space in GB
            VM_DISK_PATH="/home/ubuntu/vm-disks"
            mkdir -p $VM_DISK_PATH
            TOTAL_DISK_KB=$(df $VM_DISK_PATH | tail -1 | awk "{{print \\$4}}")
            TOTAL_DISK_GB=$((TOTAL_DISK_KB / 1024 / 1024))
            AVAILABLE_DISK_GB=$((TOTAL_DISK_GB - 5))
            
            # CPU Model
            CPU_MODEL=$(lscpu | grep "Model name" | cut -d: -f2 | sed "s/^[ \\t]*//")
            
            # Architecture
            ARCH=$(uname -m)
            
            # Hostname
            HOSTNAME=$(hostname)
            
            # Available memory
            CURRENT_FREE_RAM_MB=$(free -m | grep "^Mem:" | awk "{{print \\$7}}")
            
            # Virtualization
            VIRT_TYPE="physical"
            if which virt-what >/dev/null 2>&1; then
                VIRT_INFO=$(sudo virt-what 2>/dev/null || echo "")
                if [ -n "$VIRT_INFO" ]; then
                    VIRT_TYPE="$VIRT_INFO"
                fi
            fi
            
            # Output simple format first for debugging
            echo "DEBUG_VALUES:"
            echo "HOSTNAME=$HOSTNAME"
            echo "CPU_CORES=$CPU_CORES"
            echo "CPU_THREADS=$CPU_THREADS"
            echo "CPU_SOCKETS=$CPU_SOCKETS"
            echo "TOTAL_VCPUS=$TOTAL_VCPUS"
            echo "TOTAL_RAM_MB=$TOTAL_RAM_MB"
            echo "AVAILABLE_RAM_MB=$AVAILABLE_RAM_MB"
            echo "CURRENT_FREE_RAM_MB=$CURRENT_FREE_RAM_MB"
            echo "TOTAL_DISK_GB=$TOTAL_DISK_GB"
            echo "AVAILABLE_DISK_GB=$AVAILABLE_DISK_GB"
            echo "CPU_MODEL=$CPU_MODEL"
            echo "ARCH=$ARCH"
            echo "VIRT_TYPE=$VIRT_TYPE"
            echo "END_DEBUG"
        ' '''
        
        result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            try:
                # Parse the debug output to extract values
                output = result.stdout
                values = {}
                
                # Extract values from debug output
                for line in output.split('\n'):
                    if '=' in line and not line.startswith('DEBUG_VALUES') and not line.startswith('END_DEBUG'):
                        key, value = line.split('=', 1)
                        values[key] = value
                
                # Build the server info dictionary
                server_info = {
                    'status': 'online',
                    'hostname': values.get('HOSTNAME', 'unknown'),
                    'cpu_cores': int(values.get('CPU_CORES', 0)),
                    'cpu_threads_per_core': int(values.get('CPU_THREADS', 1)),
                    'cpu_sockets': int(values.get('CPU_SOCKETS', 1)),
                    'total_vcpus': int(values.get('TOTAL_VCPUS', 0)),
                    'usable_vcpus': max(int(values.get('TOTAL_VCPUS', 0)) - 1, 1),
                    'cpu_model': values.get('CPU_MODEL', 'Unknown'),
                    'total_ram_mb': int(values.get('TOTAL_RAM_MB', 0)),
                    'usable_ram_mb': int(values.get('AVAILABLE_RAM_MB', 0)),
                    'current_free_ram_mb': int(values.get('CURRENT_FREE_RAM_MB', 0)),
                    'total_disk_gb': int(values.get('TOTAL_DISK_GB', 0)),
                    'usable_disk_gb': max(int(values.get('AVAILABLE_DISK_GB', 0)), 10),
                    'architecture': values.get('ARCH', 'unknown'),
                    'virtualization': values.get('VIRT_TYPE', 'unknown'),
                    'detected_at': subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).decode().strip()
                }
                
                return server_info
                
            except (ValueError, KeyError) as e:
                print(f"❌ Error parsing values from {server_name}: {e}")
                print(f"Raw output: {result.stdout}")
                return {'status': 'error', 'error': 'parse_error'}
        else:
            print(f"❌ SSH failed to {server_name}: {result.stderr}")
            return {'status': 'offline', 'error': result.stderr}
            
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout connecting to {server_name}")
        return {'status': 'timeout'}
    except Exception as e:
        print(f"❌ Error getting resources from {server_name}: {e}")
        return {'status': 'error', 'error': str(e)}

def detect_all_servers():
    """Detecta recursos de todos los servidores"""
    
    servers = ['pucp-server1', 'pucp-server2', 'pucp-server3', 'pucp-server4']
    cluster_info = {
        'detection_timestamp': subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).decode().strip(),
        'servers': {}
    }
    
    print("🔍 Detectando recursos reales de servidores PUCP...")
    print("=" * 60)
    
    for server in servers:
        print(f"\n📡 Analizando {server}...")
        
        server_info = get_server_real_resources(server)
        cluster_info['servers'][server] = server_info
        
        if server_info['status'] == 'online':
            print(f"✅ {server}:")
            print(f"   • CPU: {server_info['usable_vcpus']}/{server_info['total_vcpus']} vCPUs")
            print(f"   • RAM: {server_info['usable_ram_mb']}/{server_info['total_ram_mb']} MB")
            print(f"   • Disk: {server_info['usable_disk_gb']}/{server_info['total_disk_gb']} GB")
            print(f"   • Model: {server_info['cpu_model']}")
            print(f"   • Arch: {server_info['architecture']}")
        else:
            print(f"❌ {server}: {server_info['status']}")
    
    return cluster_info

def generate_config_update(cluster_info):
    """Genera código Python actualizado para linux_driver.py"""
    
    print("\n" + "=" * 60)
    print("🔧 CONFIGURACIÓN ACTUALIZADA PARA linux_driver.py")
    print("=" * 60)
    
    print("\n# Reemplazar en /opt/pucp-orchestrator/slice_service/drivers/linux_driver.py")
    print("# Líneas ~49-72 con los valores reales detectados:\n")
    
    print("self.hypervisors = {")
    
    for server_name, info in cluster_info['servers'].items():
        if info['status'] == 'online':
            # Mapear nombre del servidor
            short_name = server_name.replace('pucp-', '')
            port = 5811 + int(short_name[-1]) - 1  # server1->5811, server2->5812, etc.
            
            print(f"    '{short_name}': {{")
            print(f"        'uri': 'qemu+ssh://ubuntu@{server_name}/system',")
            print(f"        'ip': '{server_name}',")
            print(f"        'port': {port},")
            print(f"        'max_vcpus': {info['usable_vcpus']},      # Real: {info['total_vcpus']} cores")
            print(f"        'max_ram': {info['usable_ram_mb']},       # Real: {info['total_ram_mb']} MB total")
            print(f"        'max_disk': {info['usable_disk_gb']}     # Real: {info['total_disk_gb']} GB total")
            print(f"    }},")
        else:
            short_name = server_name.replace('pucp-', '')
            print(f"    '{short_name}': {{")
            print(f"        # ❌ Server offline - using defaults")
            print(f"        'uri': 'qemu+ssh://ubuntu@{server_name}/system',")
            print(f"        'ip': '{server_name}',")
            print(f"        'port': {5811 + int(short_name[-1]) - 1},")
            print(f"        'max_vcpus': 2,")
            print(f"        'max_ram': 2048,")
            print(f"        'max_disk': 50")
            print(f"    }},")
    
    print("}")

def save_config_file(cluster_info):
    """Guarda configuración en archivo JSON"""
    
    config_file = '/opt/pucp-orchestrator/cluster_config.json'
    
    try:
        with open(config_file, 'w') as f:
            json.dump(cluster_info, f, indent=2)
        
        print(f"\n💾 Configuración guardada en: {config_file}")
        return True
    except Exception as e:
        print(f"❌ Error guardando configuración: {e}")
        return False

def main():
    """Función principal"""
    
    print("🚀 PUCP Cloud Orchestrator - Detección de Recursos Reales")
    print("=" * 70)
    
    # Detectar recursos
    cluster_info = detect_all_servers()
    
    # Generar configuración actualizada
    generate_config_update(cluster_info)
    
    # Guardar en archivo
    if save_config_file(cluster_info):
        print("\n✅ Detección completada exitosamente!")
        print("\n📋 Próximos pasos:")
        print("1. Copia la configuración generada arriba")
        print("2. Reemplaza en /opt/pucp-orchestrator/slice_service/drivers/linux_driver.py")
        print("3. Reinicia el slice-service: sudo systemctl restart pucp-slice-service")
        
        # Mostrar resumen
        online_servers = [s for s, info in cluster_info['servers'].items() if info['status'] == 'online']
        total_vcpus = sum(info.get('usable_vcpus', 0) for info in cluster_info['servers'].values() if info['status'] == 'online')
        total_ram = sum(info.get('usable_ram_mb', 0) for info in cluster_info['servers'].values() if info['status'] == 'online')
        total_disk = sum(info.get('usable_disk_gb', 0) for info in cluster_info['servers'].values() if info['status'] == 'online')
        
        print(f"\n📊 Resumen del Cluster:")
        print(f"   • Servidores online: {len(online_servers)}/4")
        print(f"   • Total vCPUs: {total_vcpus}")
        print(f"   • Total RAM: {total_ram} MB ({total_ram//1024} GB)")
        print(f"   • Total Disk: {total_disk} GB")

if __name__ == '__main__':
    main()