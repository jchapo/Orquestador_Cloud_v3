#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Linux Driver (R2)
Maneja VMs en cluster Linux usando libvirt/KVM con soporte completo para topologías
"""

import libvirt
import xml.etree.ElementTree as ET
import subprocess
import logging
import uuid
import os
import time
import json
import socket
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from base_driver import BaseDriver

logger = logging.getLogger(__name__)

class LinuxClusterDriver(BaseDriver):
    """Driver para gestionar VMs en cluster Linux usando libvirt"""
    
    def __init__(self):
        super().__init__()
        
        # Configuración del cluster según tu documento
        self.hypervisors = {
            'server1': {
                'uri': 'qemu+ssh://root@10.60.1.11/system',
                'ip': '10.60.1.11',
                'port': 5811,
                'max_vcpus': 8,
                'max_ram': 16384,  # MB
                'max_disk': 100    # GB
            },
            'server2': {
                'uri': 'qemu+ssh://root@10.60.1.12/system',
                'ip': '10.60.1.12',
                'port': 5812,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'server3': {
                'uri': 'qemu+ssh://root@10.60.1.13/system',
                'ip': '10.60.1.13',
                'port': 5813,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            },
            'server4': {
                'uri': 'qemu+ssh://root@10.60.1.14/system',
                'ip': '10.60.1.14',
                'port': 5814,
                'max_vcpus': 8,
                'max_ram': 16384,
                'max_disk': 100
            }
        }
        
        # Configuración de red (según tu topología)
        self.ovs_bridge = 'ovs1'  # OVS switch del cluster Linux
        self.network_range = '10.60.1.0/24'
        self.gateway_ip = '10.60.1.1'  # Gateway según tu documento
        
        # Storage pools
        self.storage_pools = {
            'default': '/var/lib/libvirt/images',
            'iso': '/var/lib/libvirt/iso'
        }
        
        # Imágenes disponibles
        self.available_images = {
            'ubuntu-20.04': {
                'path': '/var/lib/libvirt/images/ubuntu-20.04-server.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu20.04'
            },
            'ubuntu-22.04': {
                'path': '/var/lib/libvirt/images/ubuntu-22.04-server.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu22.04'
            },
            'centos-8': {
                'path': '/var/lib/libvirt/images/centos-8-stream.qcow2',
                'os_type': 'linux',
                'os_variant': 'centos8'
            }
        }
        
        self.connections = {}  # Cache de conexiones libvirt
    
    def get_connection(self, server_name: str) -> libvirt.virConnect:
        """Obtiene o crea conexión a un hypervisor"""
        if server_name not in self.hypervisors:
            raise ValueError(f"Unknown server: {server_name}")
        
        if server_name not in self.connections:
            try:
                uri = self.hypervisors[server_name]['uri']
                conn = libvirt.open(uri)
                if not conn:
                    raise Exception(f"Failed to connect to {uri}")
                
                self.connections[server_name] = conn
                logger.info(f"Connected to {server_name}: {uri}")
                
            except Exception as e:
                logger.error(f"Connection failed to {server_name}: {e}")
                raise
        
        return self.connections[server_name]
    
    def close_connections(self):
        """Cierra todas las conexiones"""
        for server_name, conn in self.connections.items():
            try:
                if conn and conn.isAlive():
                    conn.close()
                logger.info(f"Closed connection to {server_name}")
            except Exception as e:
                logger.warning(f"Error closing connection to {server_name}: {e}")
        
        self.connections.clear()
    
    def create_vm(self, vm_config: Dict, server_name: str, 
                  slice_id: str = None, networks: List[Dict] = None) -> Dict:
        """
        Crea una VM en el servidor especificado
        
        Args:
            vm_config: Configuración de la VM (name, cpu, ram, disk, image)
            server_name: Servidor donde crear la VM
            slice_id: ID del slice al que pertenece
            networks: Lista de redes a conectar
            
        Returns:
            Dict con información de la VM creada
        """
        conn = None
        try:
            conn = self.get_connection(server_name)
            
            # Validar configuración
            self._validate_vm_config(vm_config, server_name)
            
            # Preparar disco de la VM
            disk_path = self._prepare_vm_disk(vm_config, server_name)
            
            # Generar XML de la VM
            vm_xml = self._generate_vm_xml(
                vm_config, disk_path, server_name, slice_id, networks
            )
            
            logger.info(f"Creating VM {vm_config['name']} on {server_name}")
            logger.debug(f"VM XML: {vm_xml}")
            
            # Crear la VM
            domain = conn.createXML(vm_xml, 0)
            if not domain:
                raise Exception("Failed to create VM")
            
            # Esperar a que arranque
            self._wait_for_vm_boot(domain, timeout=60)
            
            # Obtener información de la VM
            vm_info = self._get_vm_info(domain, server_name, vm_config)
            
            logger.info(f"✓ VM {vm_config['name']} created successfully on {server_name}")
            return vm_info
            
        except Exception as e:
            logger.error(f"Failed to create VM {vm_config['name']}: {e}")
            # Cleanup en caso de error
            try:
                self._cleanup_failed_vm(vm_config['name'], server_name)
            except:
                pass
            raise
    
    def delete_vm(self, vm_name: str, server_name: str, 
                  cleanup_disk: bool = True) -> bool:
        """Elimina una VM"""
        conn = None
        try:
            conn = self.get_connection(server_name)
            
            # Buscar la VM
            try:
                domain = conn.lookupByName(vm_name)
            except libvirt.libvirtError:
                logger.warning(f"VM {vm_name} not found on {server_name}")
                return True  # Ya no existe
            
            # Parar la VM si está corriendo
            if domain.isActive():
                logger.info(f"Stopping VM {vm_name}")
                domain.destroy()  # Force shutdown
                
                # Esperar a que pare
                timeout = 30
                while timeout > 0 and domain.isActive():
                    time.sleep(1)
                    timeout -= 1
            
            # Obtener info del disco antes de eliminar
            disk_paths = []
            if cleanup_disk:
                disk_paths = self._get_vm_disk_paths(domain)
            
            # Eliminar definición de la VM
            domain.undefine()
            
            # Limpiar discos
            if cleanup_disk:
                for disk_path in disk_paths:
                    self._cleanup_disk(disk_path, server_name)
            
            logger.info(f"✓ VM {vm_name} deleted from {server_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete VM {vm_name}: {e}")
            return False
    
    def get_vm_status(self, vm_name: str, server_name: str) -> Dict:
        """Obtiene estado de una VM"""
        try:
            conn = self.get_connection(server_name)
            domain = conn.lookupByName(vm_name)
            
            return self._get_vm_info(domain, server_name, {'name': vm_name})
            
        except libvirt.libvirtError:
            return {'name': vm_name, 'status': 'not_found'}
        except Exception as e:
            logger.error(f"Error getting VM status: {e}")
            return {'name': vm_name, 'status': 'error', 'error': str(e)}
    
    def get_vm_console_url(self, vm_name: str, server_name: str) -> Optional[str]:
        """Obtiene URL de consola VNC/SPICE"""
        try:
            conn = self.get_connection(server_name)
            domain = conn.lookupByName(vm_name)
            
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            # Buscar configuración de gráficos
            graphics = root.find('.//graphics[@type="vnc"]')
            if graphics is not None:
                port = graphics.get('port')
                if port and port != '-1':
                    # Mapear puerto según tu configuración
                    mapped_port = self.hypervisors[server_name]['port']
                    return f"vnc://{self.gateway_ip}:{mapped_port}"
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get console URL: {e}")
            return None
    
    def list_vms(self, server_name: str = None) -> List[Dict]:
        """Lista todas las VMs"""
        vms = []
        
        servers = [server_name] if server_name else self.hypervisors.keys()
        
        for srv in servers:
            try:
                conn = self.get_connection(srv)
                domains = conn.listAllDomains()
                
                for domain in domains:
                    vm_info = self._get_vm_info(domain, srv, {'name': domain.name()})
                    vms.append(vm_info)
                    
            except Exception as e:
                logger.error(f"Error listing VMs on {srv}: {e}")
        
        return vms
    
    def get_server_resources(self, server_name: str = None) -> List[Dict]:
        """Obtiene información de recursos de servidores"""
        resources = []
        
        servers = [server_name] if server_name else self.hypervisors.keys()
        
        for srv in servers:
            try:
                conn = self.get_connection(srv)
                
                # Información del host
                host_info = conn.getInfo()
                node_info = conn.getNodeInfo()
                
                # Calcular recursos usados
                domains = conn.listAllDomains()
                used_vcpus = 0
                used_ram = 0
                
                for domain in domains:
                    if domain.isActive():
                        domain_info = domain.info()
                        used_vcpus += domain_info[3]  # Number of virtual CPUs
                        used_ram += domain_info[2] // 1024  # Memory in MB
                
                server_config = self.hypervisors[srv]
                
                resource_info = {
                    'hostname': srv,
                    'ip': server_config['ip'],
                    'infrastructure': 'linux',
                    'status': 'active' if conn.isAlive() else 'inactive',
                    'total_vcpus': server_config['max_vcpus'],
                    'used_vcpus': used_vcpus,
                    'available_vcpus': server_config['max_vcpus'] - used_vcpus,
                    'total_ram': server_config['max_ram'],
                    'used_ram': used_ram,
                    'available_ram': server_config['max_ram'] - used_ram,
                    'total_disk': server_config['max_disk'],
                    'used_disk': self._get_used_disk_space(srv),
                    'active_vms': len([d for d in domains if d.isActive()]),
                    'total_vms': len(domains),
                    'cpu_utilization': (used_vcpus / server_config['max_vcpus']) * 100,
                    'ram_utilization': (used_ram / server_config['max_ram']) * 100,
                    'last_updated': datetime.utcnow().isoformat()
                }
                
                resources.append(resource_info)
                
            except Exception as e:
                logger.error(f"Error getting resources for {srv}: {e}")
                # Agregar info básica aunque falle la conexión
                resources.append({
                    'hostname': srv,
                    'infrastructure': 'linux',
                    'status': 'error',
                    'error': str(e)
                })
        
        return resources
    
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """
        Despliega un slice completo con sus VMs y redes
        
        Args:
            slice_config: Configuración del slice
            placement: Resultado del VM placement {vm_name: server_assignment}
            
        Returns:
            Dict con resultados del deployment
        """
        deployed_vms = []
        created_networks = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            # 1. Crear redes primero
            logger.info(f"Creating networks for slice {slice_id}")
            for network in slice_config.get('networks', []):
                try:
                    network_result = self._create_slice_network(network, slice_id)
                    created_networks.append(network_result)
                    logger.info(f"✓ Network {network['name']} created")
                except Exception as e:
                    error_msg = f"Failed to create network {network['name']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 2. Crear VMs según placement
            logger.info(f"Creating VMs for slice {slice_id}")
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                
                if vm_name not in placement:
                    error_msg = f"No placement found for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                
                server_assignment = placement[vm_name]
                server_name = server_assignment['hostname']
                
                try:
                    # Preparar configuración de VM para el driver
                    driver_vm_config = {
                        'name': vm_name,
                        'cpu': vm_config.get('cpu', 1),
                        'ram': vm_config.get('ram', 1024),
                        'disk': vm_config.get('disk', 10),
                        'image': vm_config.get('image', 'ubuntu-20.04')
                    }
                    
                    vm_result = self.create_vm(
                        driver_vm_config, 
                        server_name, 
                        slice_id, 
                        created_networks
                    )
                    
                    deployed_vms.append(vm_result)
                    logger.info(f"✓ VM {vm_name} deployed on {server_name}")
                    
                except Exception as e:
                    error_msg = f"Failed to deploy VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 3. Configurar conectividad entre VMs si se especifica
            if 'connections' in slice_config:
                logger.info(f"Configuring VM connections for slice {slice_id}")
                self._configure_vm_connections(
                    slice_config['connections'], 
                    deployed_vms, 
                    created_networks
                )
            
            deployment_result = {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'errors': errors,
                'summary': {
                    'total_vms': len(slice_config.get('nodes', [])),
                    'deployed_vms': len(deployed_vms),
                    'total_networks': len(slice_config.get('networks', [])),
                    'created_networks': len(created_networks),
                    'deployment_time': datetime.utcnow().isoformat()
                }
            }
            
            if errors:
                logger.warning(f"Slice {slice_id} deployed with {len(errors)} errors")
            else:
                logger.info(f"✓ Slice {slice_id} deployed successfully")
            
            return deployment_result
            
        except Exception as e:
            logger.error(f"Critical error deploying slice {slice_id}: {e}")
            
            # Cleanup en caso de error crítico
            self._cleanup_slice_deployment(deployed_vms, created_networks)
            
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }
    
    def destroy_slice(self, slice_id: str, vm_list: List[Dict]) -> Dict:
        """Elimina un slice completo"""
        deleted_vms = []
        errors = []
        
        try:
            logger.info(f"Destroying slice {slice_id}")
            
            for vm_info in vm_list:
                try:
                    vm_name = vm_info['name']
                    server_name = vm_info.get('assigned_host') or vm_info.get('server')
                    
                    if not server_name:
                        logger.warning(f"No server info for VM {vm_name}")
                        continue
                    
                    success = self.delete_vm(vm_name, server_name, cleanup_disk=True)
                    if success:
                        deleted_vms.append(vm_name)
                        logger.info(f"✓ VM {vm_name} deleted")
                    else:
                        errors.append(f"Failed to delete VM {vm_name}")
                        
                except Exception as e:
                    error_msg = f"Error deleting VM {vm_info.get('name', 'unknown')}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Cleanup de redes del slice
            try:
                self._cleanup_slice_networks(slice_id)
            except Exception as e:
                errors.append(f"Network cleanup error: {e}")
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deleted_vms': deleted_vms,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Critical error destroying slice {slice_id}: {e}")
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deleted_vms': deleted_vms
            }
    
    # Métodos privados auxiliares
    
    def _validate_vm_config(self, vm_config: Dict, server_name: str):
        """Valida configuración de VM"""
        required_fields = ['name', 'cpu', 'ram', 'disk', 'image']
        for field in required_fields:
            if field not in vm_config:
                raise ValueError(f"Missing required field: {field}")
        
        # Validar imagen
        if vm_config['image'] not in self.available_images:
            raise ValueError(f"Unknown image: {vm_config['image']}")
        
        # Validar recursos
        server_config = self.hypervisors[server_name]
        if vm_config['cpu'] > server_config['max_vcpus']:
            raise ValueError(f"CPU count exceeds server limit")
        if vm_config['ram'] > server_config['max_ram']:
            raise ValueError(f"RAM exceeds server limit")
    
    def _prepare_vm_disk(self, vm_config: Dict, server_name: str) -> str:
        """Prepara disco de la VM"""
        vm_name = vm_config['name']
        base_image = self.available_images[vm_config['image']]['path']
        vm_disk_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
        
        # Crear disco usando qemu-img con backing file
        cmd = [
            'qemu-img', 'create', '-f', 'qcow2',
            '-F', 'qcow2', '-b', base_image,
            vm_disk_path, f"{vm_config['disk']}G"
        ]
        
        # Ejecutar comando en el servidor remoto
        server_ip = self.hypervisors[server_name]['ip']
        ssh_cmd = ['ssh', f'root@{server_ip}'] + cmd
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
            logger.info(f"Disk created: {vm_disk_path}")
            return vm_disk_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create disk: {e.stderr}")
            raise Exception(f"Disk creation failed: {e.stderr}")
    
    def _generate_vm_xml(self, vm_config: Dict, disk_path: str, 
                        server_name: str, slice_id: str = None, 
                        networks: List[Dict] = None) -> str:
        """Genera XML de configuración de la VM"""
        
        vm_name = vm_config['name']
        vm_uuid = str(uuid.uuid4())
        ram_mb = vm_config['ram']
        vcpus = vm_config['cpu']
        
        # Generar MAC address única
        mac_address = self._generate_mac_address(vm_name, server_name)
        
        xml_template = f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <uuid>{vm_uuid}</uuid>
  <metadata>
    <pucp:slice_id xmlns:pucp='http://pucp.edu.pe/orchestrator'>{slice_id or 'unknown'}</pucp:slice_id>
    <pucp:server xmlns:pucp='http://pucp.edu.pe/orchestrator'>{server_name}</pucp:server>
  </metadata>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-5.2'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
    </disk>
    <controller type='usb' index='0' model='qemu-xhci' ports='15'>
      <address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
    </controller>
    <controller type='sata' index='0'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x1f' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='1' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='1' port='0x10'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0' multifunction='on'/>
    </controller>
    <controller type='pci' index='2' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='2' port='0x11'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x1'/>
    </controller>
    <controller type='pci' index='3' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='3' port='0x12'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x2'/>
    </controller>
    <controller type='pci' index='4' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='4' port='0x13'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x3'/>
    </controller>
    <controller type='virtio-serial' index='0'>
      <address type='pci' domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
    </controller>
    <interface type='bridge'>
      <mac address='{mac_address}'/>
      <source bridge='{self.ovs_bridge}'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
      <address type='virtio-serial' controller='0' bus='0' port='1'/>
    </channel>
    <input type='tablet' bus='usb'>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <sound model='ich9'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x1b' function='0x0'/>
    </sound>
    <video>
      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <address type='pci' domain='0x0000' bus='0x05' slot='0x00' function='0x0'/>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
      <address type='pci' domain='0x0000' bus='0x06' slot='0x00' function='0x0'/>
    </rng>
  </devices>
</domain>"""
        
        return xml_template
    
    def _generate_mac_address(self, vm_name: str, server_name: str) -> str:
        """Genera MAC address única para la VM"""
        # Usar hash del nombre + servidor para generar MAC consistente
        import hashlib
        hash_input = f"{vm_name}-{server_name}".encode()
        hash_value = hashlib.md5(hash_input).hexdigest()
        
        # Formato MAC: 52:54:00:XX:XX:XX (prefijo KVM)
        mac = f"52:54:00:{hash_value[0:2]}:{hash_value[2:4]}:{hash_value[4:6]}"
        return mac
    
    def _wait_for_vm_boot(self, domain, timeout: int = 60):
        """Espera a que la VM arranque completamente"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                state = domain.state()[0]
                if state == libvirt.VIR_DOMAIN_RUNNING:
                    logger.info(f"VM {domain.name()} is running")
                    return True
                elif state == libvirt.VIR_DOMAIN_SHUTOFF:
                    raise Exception("VM failed to start - shutoff state")
                    
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Error checking VM state: {e}")
                break
        
            raise Exception(f"VM {domain.name()} failed to boot within {timeout} seconds")

    def _get_vm_info(self, domain, server_name: str, vm_config: Dict) -> Dict:
        """Obtiene información completa de una VM"""
        try:
            # Información básica del dominio
            vm_info = domain.info()
            state_names = {
                libvirt.VIR_DOMAIN_NOSTATE: 'no_state',
                libvirt.VIR_DOMAIN_RUNNING: 'running', 
                libvirt.VIR_DOMAIN_BLOCKED: 'blocked',
                libvirt.VIR_DOMAIN_PAUSED: 'paused',
                libvirt.VIR_DOMAIN_SHUTDOWN: 'shutdown',
                libvirt.VIR_DOMAIN_SHUTOFF: 'shutoff',
                libvirt.VIR_DOMAIN_CRASHED: 'crashed'
            }
            
            # Obtener IP de la VM
            ip_address = self._get_vm_ip_address(domain)
            
            # Obtener puerto VNC
            vnc_port = self._get_vnc_port(domain)
            console_url = None
            if vnc_port:
                mapped_port = self.hypervisors[server_name]['port']
                console_url = f"vnc://{self.gateway_ip}:{mapped_port}"
            
            # Obtener metadata del slice
            slice_id = self._get_vm_slice_id(domain)
            
            return {
                'vm_id': domain.UUIDString(),
                'name': domain.name(),
                'status': state_names.get(vm_info[0], 'unknown'),
                'server': server_name,
                'server_ip': self.hypervisors[server_name]['ip'],
                'vcpus': vm_info[3],
                'ram_mb': vm_info[2] // 1024,
                'max_ram_mb': vm_info[1] // 1024,
                'cpu_time': vm_info[4],
                'ip_address': ip_address,
                'console_url': console_url,
                'vnc_port': vnc_port,
                'slice_id': slice_id,
                'created_at': datetime.utcnow().isoformat(),
                'is_active': domain.isActive() == 1,
                'autostart': domain.autostart() == 1
            }
            
        except Exception as e:
            logger.error(f"Error getting VM info: {e}")
            return {
                'vm_id': domain.UUIDString() if domain else None,
                'name': vm_config.get('name', 'unknown'),
                'status': 'error',
                'server': server_name,
                'error': str(e)
            }
    
    def _get_vm_ip_address(self, domain) -> Optional[str]:
        """Obtiene dirección IP de la VM"""
        try:
            # Método 1: DHCP leases (más confiable)
            ifaces = domain.interfaceAddresses(
                libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
            )
            
            for name, iface in ifaces.items():
                if iface['addrs']:
                    for addr in iface['addrs']:
                        if addr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                            return addr['addr']
            
            # Método 2: Guest agent (si está disponible)
            try:
                ifaces = domain.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
                )
                for name, iface in ifaces.items():
                    if iface['addrs']:
                        for addr in iface['addrs']:
                            if addr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
                                return addr['addr']
            except:
                pass
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get VM IP: {e}")
            return None
    
    def _get_vnc_port(self, domain) -> Optional[int]:
        """Obtiene puerto VNC de la VM"""
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            graphics = root.find('.//graphics[@type="vnc"]')
            if graphics is not None:
                port = graphics.get('port')
                if port and port != '-1':
                    return int(port)
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get VNC port: {e}")
            return None
    
    def _get_vm_slice_id(self, domain) -> Optional[str]:
        """Obtiene slice_id del metadata de la VM"""
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            # Buscar en metadata
            slice_elem = root.find('.//{http://pucp.edu.pe/orchestrator}slice_id')
            if slice_elem is not None:
                return slice_elem.text
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get slice ID: {e}")
            return None
    
    def _get_vm_disk_paths(self, domain) -> List[str]:
        """Obtiene rutas de discos de la VM"""
        disk_paths = []
        try:
            xml_desc = domain.XMLDesc()
            root = ET.fromstring(xml_desc)
            
            disks = root.findall('.//disk[@type="file"]')
            for disk in disks:
                source = disk.find('source')
                if source is not None:
                    file_path = source.get('file')
                    if file_path:
                        disk_paths.append(file_path)
            
        except Exception as e:
            logger.error(f"Error getting disk paths: {e}")
        
        return disk_paths
    
    def _cleanup_disk(self, disk_path: str, server_name: str):
        """Elimina archivo de disco"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            ssh_cmd = ['ssh', f'root@{server_ip}', 'rm', '-f', disk_path]
            
            subprocess.run(ssh_cmd, check=True, capture_output=True)
            logger.info(f"Disk removed: {disk_path}")
            
        except Exception as e:
            logger.warning(f"Failed to remove disk {disk_path}: {e}")
    
    def _get_used_disk_space(self, server_name: str) -> int:
        """Obtiene espacio de disco usado en GB"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            cmd = ['ssh', f'root@{server_ip}', 'du', '-s', '/var/lib/libvirt/images']
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Resultado en KB, convertir a GB
            kb_used = int(result.stdout.split()[0])
            gb_used = kb_used // (1024 * 1024)
            
            return gb_used
            
        except Exception as e:
            logger.warning(f"Could not get disk usage for {server_name}: {e}")
            return 0
    
    def _create_slice_network(self, network_config: Dict, slice_id: str) -> Dict:
        """Crea red para el slice"""
        try:
            # Para Linux cluster, las redes se manejan a través de OVS
            # Este método coordina con el network_service
            
            network_name = f"{slice_id}-{network_config['name']}"
            
            # Llamar al network service para crear la red
            import requests
            network_data = {
                'name': network_name,
                'cidr': network_config['cidr'],
                'infrastructure': 'linux',
                'slice_id': slice_id,
                'gateway': network_config.get('gateway'),
                'dns_servers': network_config.get('dns_servers', ['8.8.8.8'])
            }
            
            # En producción esto sería una llamada HTTP al network_service
            # Por ahora simulamos la creación
            logger.info(f"Network {network_name} created for slice {slice_id}")
            
            return {
                'name': network_name,
                'cidr': network_config['cidr'],
                'vlan_id': None,  # Se asignaría por el network_service
                'status': 'active'
            }
            
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            raise
    
    def _configure_vm_connections(self, connections: List[Dict], 
                                deployed_vms: List[Dict], 
                                networks: List[Dict]):
        """Configura conexiones entre VMs"""
        try:
            # Este método configuraría las conexiones específicas
            # entre VMs usando OVS flows o iptables según la topología
            
            for connection in connections:
                source_vm = connection.get('from') or connection.get('source')
                target_vm = connection.get('to') or connection.get('target')
                network_name = connection.get('network', 'default')
                
                logger.info(f"Configuring connection: {source_vm} -> {target_vm} via {network_name}")
                
                # Aquí se implementaría la lógica específica de conectividad
                # Por ejemplo, configurar flows en OVS, reglas de firewall, etc.
                
        except Exception as e:
            logger.error(f"Error configuring VM connections: {e}")
    
    def _cleanup_slice_networks(self, slice_id: str):
        """Limpia redes del slice"""
        try:
            # Eliminar redes creadas para este slice
            # Esto coordinaría con el network_service
            
            logger.info(f"Cleaning up networks for slice {slice_id}")
            
            # Llamar al network service para cleanup
            # Por ahora solo log
            
        except Exception as e:
            logger.error(f"Error cleaning up networks: {e}")
    
    def _cleanup_failed_vm(self, vm_name: str, server_name: str):
        """Limpia VM que falló en la creación"""
        try:
            conn = self.get_connection(server_name)
            
            # Intentar eliminar definición si existe
            try:
                domain = conn.lookupByName(vm_name)
                if domain.isActive():
                    domain.destroy()
                domain.undefine()
            except:
                pass
            
            # Limpiar disco si existe
            disk_path = f"/var/lib/libvirt/images/{vm_name}.qcow2"
            self._cleanup_disk(disk_path, server_name)
            
        except Exception as e:
            logger.warning(f"Cleanup failed for VM {vm_name}: {e}")
    
    def _cleanup_slice_deployment(self, deployed_vms: List[Dict], 
                                 created_networks: List[Dict]):
        """Limpia deployment fallido de slice"""
        try:
            logger.info("Cleaning up failed slice deployment")
            
            # Eliminar VMs creadas
            for vm_info in deployed_vms:
                try:
                    self.delete_vm(vm_info['name'], vm_info['server'])
                except Exception as e:
                    logger.warning(f"Failed to cleanup VM {vm_info['name']}: {e}")
            
            # Limpiar redes
            for network in created_networks:
                try:
                    # Cleanup de red
                    pass
                except Exception as e:
                    logger.warning(f"Failed to cleanup network {network['name']}: {e}")
                    
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Destructor para cerrar conexiones"""
        self.close_connections()    