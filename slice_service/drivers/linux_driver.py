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
import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .base_driver import BaseDriver

logger = logging.getLogger(__name__)

class LinuxClusterDriver(BaseDriver):
    """Driver para gestionar VMs en cluster Linux usando libvirt"""
    
    def __init__(self, token=None):
        super().__init__()
        
        # Configuración del cluster según tu documento
        self.hypervisors = {
            'server1': {
            'uri': 'qemu+ssh://ubuntu@pucp-server1/system',
                'ip': 'pucp-server1',
                'port': 5811,
                'max_vcpus': 3,      # Real: 4 cores
                'max_ram': 3423,       # Real: 3935 MB total
                'max_disk': 10     # Real: 4 GB total
            },
            'server2': {
                'uri': 'qemu+ssh://ubuntu@pucp-server2/system',
                'ip': 'pucp-server2',
                'port': 5812,
                'max_vcpus': 3,      # Real: 4 cores
                'max_ram': 3423,       # Real: 3935 MB total
                'max_disk': 10     # Real: 5 GB total
            },
            'server3': {
                'uri': 'qemu+ssh://ubuntu@pucp-server3/system',
                'ip': 'pucp-server3',
                'port': 5813,
                'max_vcpus': 3,      # Real: 4 cores
                'max_ram': 3423,       # Real: 3935 MB total
                'max_disk': 10     # Real: 4 GB total
            },
            'server4': {
                'uri': 'qemu+ssh://ubuntu@pucp-server4/system',
                'ip': 'pucp-server4',
                'port': 5814,
                'max_vcpus': 3,      # Real: 4 cores
                'max_ram': 7433,       # Real: 7945 MB total
                'max_disk': 10     # Real: 5 GB total
            },
        }

        self.network_client = NetworkServiceClient(token=self._get_service_token())

        self.network_config = {
            'management': {
                'bridge': 'br-mgmt',
                'cidr': '192.168.201.0/24',
                'gateway': '192.168.201.1',
                'vlan_id': None,
                'internet_access': False,
                'use_network_service': False  # Management no usa Network Service
            },
            'trunk': {
                'bridge': 'ovs1',
                'cidr': '10.60.1.0/24',
                'gateway': '10.60.1.1',
                'vlan_range': (100, 199),
                'internet_access': True,
                'use_network_service': True,  # ← Usar Network Service
                'is_provider': False
            },
            'data': {
                'bridge': 'ovs1',
                'vlan_range': (200, 299),
                'internet_access': False,
                'use_network_service': True,  # ← Usar Network Service
                'is_provider': False
            },
            'provider': {
                'bridge': 'ovs1',
                'vlan_range': (300, 399),
                'internet_access': True,
                'use_network_service': True,  # ← Usar Network Service
                'is_provider': True          # ← Red provider
            }
        }

        self.server_interfaces = {
            'server1': {
                'management': 'ens3',
                'trunk': 'ens4'
            },
            'server2': {
                'management': 'ens3', 
                'trunk': 'ens4'
            },
            'server3': {
                'management': 'ens3',
                'trunk': 'ens4'
            },
            'server4': {
                'management': 'ens3',
                'trunk': 'ens4'
            }
        }
        
        # Configuración de red (según tu topología)
        self.ovs_bridge = 'ovs1'  # OVS switch del cluster Linux
        self.network_range = '192.168.201.0/24'
        self.gateway_ip = '192.168.201.1'  # Gateway según tu documento
        
        # Storage pools
        self.storage_pools = {
            'default': '/var/lib/libvirt/images',
            'iso': '/var/lib/libvirt/iso'
        }
        
        # Imágenes disponibles
        self.available_images = {
            'ubuntu-20.04-server': {
                'path': '/home/ubuntu/vm-images/ubuntu-20.04-server.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu20.04'
            },
            'alpine-network': {
                'path': '/home/ubuntu/vm-images/alpine-network.qcow2',
                'os_type': 'linux',
                'os_variant': 'alpinelinux3.18'
            },
            'ubuntu-22.04-minimal': {
                'path': '/home/ubuntu/vm-images/ubuntu-22.04-minimal.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu20.04'
            },
            'network-tools': {
                'path': '/home/ubuntu/vm-images/network-tools.qcow2',
                'os_type': 'linux',
                'os_variant': 'generic'
            },
            'ubuntu-22.04-minimal': {
                'path': '/home/ubuntu/vm-images/ubuntu-22.04-minimal.qcow2',
                'os_type': 'linux',
                'os_variant': 'ubuntu22.04'
            },
            'cirros-0.5.2': {
                'path': '/home/ubuntu/vm-images/cirros-0.5.2.qcow2',
                'os_type': 'linux',
                'os_variant': 'generic'
            },
            'centos-8-minimal': {
                'path': '/home/ubuntu/vm-images/centos-8-minimal.qcow2',
                'os_type': 'linux',
                'os_variant': 'centos8'
            }
        }
        
        self.connections = {}  # Cache de conexiones libvirt

        self.ip_pools = {
            'trunk': {
                'cidr': '10.60.1.0/24',
                'gateway': '10.60.1.1',
                'start': 10,  # 10.60.1.10
                'end': 200,   # 10.60.1.200
                'reserved': {}  # {ip: vm_info}
            },
            'data': {
                'cidr': '192.168.100.0/24', 
                'gateway': '192.168.100.1',
                'start': 10,
                'end': 200,
                'reserved': {}
            },
            'provider': {
                'cidr': '10.60.2.0/24',
                'gateway': '10.60.2.1', 
                'start': 10,
                'end': 200,
                'reserved': {}
            }
        }
    

    def pre_allocate_vm_ip(self, vm_config: Dict, network_type: str, slice_id: str) -> Optional[str]:
        """
        Pre-asigna una IP para una VM antes de crearla
        
        Args:
            vm_config: Configuración de la VM
            network_type: Tipo de red (trunk, data, provider)
            slice_id: ID del slice
            
        Returns:
            IP asignada o None si no se pudo asignar
        """
        try:
            vm_name = vm_config['name']
            has_internet = vm_config.get('internet_access', False)
            
            logger.info(f"Pre-asignando IP para VM {vm_name} (internet: {has_internet})")
            
            if network_type not in self.ip_pools:
                logger.error(f"Network type {network_type} not supported")
                return None
                
            pool = self.ip_pools[network_type]
            network = ipaddress.IPv4Network(pool['cidr'])
            base_ip = str(network.network_address)
            
            # Para VMs con internet, asignar IPs bajas (más fáciles de recordar)
            if has_internet:
                start_range = pool['start']
                end_range = min(pool['start'] + 20, pool['end'])
                logger.info(f"VM {vm_name} con internet - buscando IP en rango {start_range}-{end_range}")
            else:
                start_range = pool['start'] + 50  # IPs más altas para VMs sin internet
                end_range = pool['end']
                logger.info(f"VM {vm_name} sin internet - buscando IP en rango {start_range}-{end_range}")
            
            # Buscar IP disponible
            for host_part in range(start_range, end_range + 1):
                candidate_ip = str(network.network_address + host_part)
                
                # Verificar que no esté reservada
                if candidate_ip not in pool['reserved']:
                    # Verificar que no esté en uso en el sistema
                    if not self._is_ip_in_use(candidate_ip, network_type):
                        # Reservar la IP
                        pool['reserved'][candidate_ip] = {
                            'vm_name': vm_name,
                            'slice_id': slice_id,
                            'internet_access': has_internet,
                            'assigned_at': datetime.utcnow().isoformat(),
                            'network_type': network_type
                        }
                        
                        logger.info(f"✅ IP {candidate_ip} pre-asignada a VM {vm_name}")
                        return candidate_ip
            
            logger.error(f"❌ No hay IPs disponibles en pool {network_type} para VM {vm_name}")
            return None
            
        except Exception as e:
            logger.error(f"Error pre-asignando IP para VM {vm_name}: {e}")
            return None
    
    def _is_ip_in_use(self, ip: str, network_type: str) -> bool:
        """Verifica si una IP está en uso en el sistema"""
        try:
            # Ping test - si responde está en uso
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                  capture_output=True, timeout=3)
            if result.returncode == 0:
                logger.debug(f"IP {ip} responde a ping - en uso")
                return True
            
            # Verificar en ARP table
            arp_result = subprocess.run(['arp', '-n', ip], 
                                      capture_output=True, text=True)
            if "no entry" not in arp_result.stdout.lower():
                logger.debug(f"IP {ip} en ARP table - en uso")  
                return True
                
            # Verificar en DHCP leases
            dhcp_check = subprocess.run(['grep', '-r', ip, '/var/lib/dhcp/'], 
                                      capture_output=True, text=True)
            if dhcp_check.returncode == 0:
                logger.debug(f"IP {ip} en DHCP leases - en uso")
                return True
                
            return False
            
        except Exception as e:
            logger.warning(f"Error verificando IP {ip}: {e}")
            return False  # En caso de error, asumir disponible

    def create_vm_with_fixed_ip(self, vm_config: Dict, server_name: str, 
                               slice_id: str, networks: List[Dict]) -> Dict:
        """
        Crea VM con IP pre-asignada
        """
        try:
            vm_name = vm_config['name'] 
            has_internet = vm_config.get('internet_access', False)
            
            logger.info(f"Creando VM {vm_name} con IP fija (internet: {has_internet})")
            
            # 1. Determinar tipo de red principal
            main_network_type = 'trunk' if has_internet else 'data'
            for network in networks:
                if network.get('internet_access') == has_internet:
                    main_network_type = network.get('type', main_network_type)
                    break
            
            # 2. Pre-asignar IP
            assigned_ip = self.pre_allocate_vm_ip(vm_config, main_network_type, slice_id)
            if not assigned_ip:
                raise Exception(f"No se pudo pre-asignar IP para VM {vm_name}")
            
            # 3. Configurar DHCP reservation ANTES de crear la VM
            mac_address = self._generate_mac_address(vm_name)
            self._configure_dhcp_reservation(assigned_ip, mac_address, vm_name, main_network_type)
            
            # 4. Actualizar configuración de VM con IP y MAC fijas
            enhanced_vm_config = vm_config.copy()
            enhanced_vm_config['fixed_ip'] = assigned_ip
            enhanced_vm_config['mac_address'] = mac_address
            enhanced_vm_config['network_type'] = main_network_type
            
            # 5. Crear VM con configuración mejorada
            vm_result = self.create_vm(enhanced_vm_config, server_name, slice_id, networks)
            
            # 6. Verificar que obtuvo la IP correcta
            actual_ip = self._verify_vm_ip(vm_name, server_name, assigned_ip)
            if actual_ip == assigned_ip:
                logger.info(f"✅ VM {vm_name} creada con IP fija {assigned_ip}")
                vm_result['ip_address'] = assigned_ip
                vm_result['ip_assignment'] = 'fixed'
            else:
                logger.warning(f"⚠️ VM {vm_name} obtuvo IP {actual_ip} en lugar de {assigned_ip}")
                vm_result['ip_address'] = actual_ip
                vm_result['ip_assignment'] = 'dynamic'
            
            # 7. Configurar acceso desde exterior si tiene internet
            if has_internet:
                external_port = self._configure_external_access(vm_name, assigned_ip, server_name)
                if external_port:
                    vm_result['external_ssh_port'] = external_port
                    vm_result['external_access'] = f"ssh ubuntu@{self.hypervisors[server_name]['ip']} -p {external_port}"
            
            return vm_result
            
        except Exception as e:
            # Cleanup en caso de error
            if 'assigned_ip' in locals():
                self._release_ip(assigned_ip, main_network_type)
            logger.error(f"Error creando VM {vm_name} con IP fija: {e}")
            raise

    def _generate_mac_address(self, vm_name: str) -> str:
        """Genera MAC address determinística para una VM"""
        # Usar hash del nombre para generar MAC consistente
        import hashlib
        hash_obj = hashlib.md5(vm_name.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Construir MAC con prefijo VMware OUI + hash
        mac = f"52:54:00:{hash_hex[0:2]}:{hash_hex[2:4]}:{hash_hex[4:6]}"
        logger.debug(f"Generated MAC for {vm_name}: {mac}")
        return mac

    def _configure_dhcp_reservation(self, ip: str, mac: str, vm_name: str, network_type: str):
        """Configura reservación DHCP para la VM"""
        try:
            pool = self.ip_pools[network_type]
            gateway = pool['gateway']
            cidr = pool['cidr']
            
            # Determinar interface de red
            if network_type == 'trunk':
                interface = 'vlan101'  # Basado en tu configuración actual
            elif network_type == 'data':
                interface = 'vlan102'
            else:
                interface = f'vlan{network_type}'
            
            # Crear configuración DHCP específica
            dhcp_config = f"""
# DHCP config for {vm_name}
subnet {ipaddress.IPv4Network(cidr).network_address} netmask {ipaddress.IPv4Network(cidr).netmask} {{
    range {ip} {ip};
    option routers {gateway};
    option domain-name-servers 8.8.8.8, 1.1.1.1;
    option broadcast-address {ipaddress.IPv4Network(cidr).broadcast_address};
    default-lease-time 86400;
    max-lease-time 172800;
    
    host {vm_name} {{
        hardware ethernet {mac};
        fixed-address {ip};
        option host-name "{vm_name}";
    }}
}}
"""
            
            # Aplicar configuración en el servidor principal
            commands = [
                f"sudo mkdir -p /etc/dhcp/reservations",
                f"sudo tee /etc/dhcp/reservations/{vm_name}.conf > /dev/null << 'EOF'\n{dhcp_config}\nEOF",
                f"sudo systemctl restart isc-dhcp-server || sudo dhcpd -cf /etc/dhcp/reservations/{vm_name}.conf -pf /var/run/dhcpd-{vm_name}.pid {interface} &"
            ]
            
            for server_name in ['server1']:  # Configurar en servidor principal
                server_ip = self.hypervisors[server_name]['ip']
                for cmd in commands:
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"DHCP config command failed: {cmd} - {e.stderr}")
            
            logger.info(f"✅ DHCP reservation configured: {vm_name} -> {ip} ({mac})")
            
        except Exception as e:
            logger.error(f"Error configuring DHCP reservation: {e}")
            raise

    def _verify_vm_ip(self, vm_name: str, server_name: str, expected_ip: str, timeout: int = 60) -> Optional[str]:
        """Verifica que la VM obtuvo la IP esperada"""
        try:
            import time
            
            conn = self.get_connection(server_name)
            domain = conn.lookupByName(vm_name)
            
            # Esperar hasta que la VM obtenga IP
            for attempt in range(timeout):
                time.sleep(1)
                
                # Método 1: libvirt
                try:
                    result = subprocess.run(['ssh', f'ubuntu@{self.hypervisors[server_name]["ip"]}', 
                                           f'virsh domifaddr {vm_name}'], 
                                          capture_output=True, text=True, timeout=10)
                    if expected_ip in result.stdout:
                        logger.info(f"✅ VM {vm_name} confirmed with IP {expected_ip}")
                        return expected_ip
                except:
                    pass
                
                # Método 2: ping test
                try:
                    ping_result = subprocess.run(['ping', '-c', '1', '-W', '1', expected_ip], 
                                               capture_output=True, timeout=3)
                    if ping_result.returncode == 0:
                        logger.info(f"✅ VM {vm_name} responding at {expected_ip}")
                        return expected_ip
                except:
                    pass
                
                if attempt % 10 == 0:
                    logger.debug(f"Waiting for VM {vm_name} to get IP {expected_ip} (attempt {attempt+1}/{timeout})")
            
            logger.warning(f"⚠️ VM {vm_name} did not get expected IP {expected_ip} within {timeout}s")
            return None
            
        except Exception as e:
            logger.error(f"Error verifying VM IP: {e}")
            return None

    def _configure_external_access(self, vm_name: str, vm_ip: str, server_name: str) -> Optional[int]:
        """Configura acceso externo para VM con internet"""
        try:
            # Generar puerto único basado en VM
            import hashlib
            port_hash = int(hashlib.md5(vm_name.encode()).hexdigest()[:4], 16)
            external_port = 2200 + (port_hash % 800)  # Rango 2200-2999
            
            server_ip = self.hypervisors[server_name]['ip']
            
            # Configurar port forwarding
            port_forward_commands = [
                # SSH access
                f"sudo iptables -t nat -A PREROUTING -p tcp --dport {external_port} -j DNAT --to-destination {vm_ip}:22",
                f"sudo iptables -A FORWARD -p tcp -d {vm_ip} --dport 22 -j ACCEPT",
                
                # HTTP access (puerto 8080 externo -> 80 interno)
                f"sudo iptables -t nat -A PREROUTING -p tcp --dport {external_port + 100} -j DNAT --to-destination {vm_ip}:80",
                f"sudo iptables -A FORWARD -p tcp -d {vm_ip} --dport 80 -j ACCEPT"
            ]
            
            for cmd in port_forward_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Port forward command failed: {cmd} - {e.stderr}")
            
            logger.info(f"✅ External access configured for {vm_name}:")
            logger.info(f"   SSH: ssh ubuntu@{server_ip} -p {external_port}")
            logger.info(f"   HTTP: http://{server_ip}:{external_port + 100}")
            
            return external_port
            
        except Exception as e:
            logger.error(f"Error configuring external access: {e}")
            return None

    def _release_ip(self, ip: str, network_type: str):
        """Libera una IP del pool"""
        try:
            if network_type in self.ip_pools and ip in self.ip_pools[network_type]['reserved']:
                del self.ip_pools[network_type]['reserved'][ip]
                logger.info(f"✅ IP {ip} released from {network_type} pool")
        except Exception as e:
            logger.error(f"Error releasing IP {ip}: {e}")

    def deploy_slice_enhanced(self, slice_config: Dict, placement: Dict) -> Dict:
        """
        Deploy slice con pre-asignación de IPs
        """
        deployed_vms = []
        created_networks = []
        errors = []
        ip_assignments = {}
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            logger.info(f"🚀 Deploying slice {slice_id} with IP pre-assignment")
            
            # 1. Configurar redes primero
            network_result = self.setup_slice_networks(slice_config, slice_id)
            if not network_result['success']:
                errors.extend(network_result['errors'])
            created_networks = network_result['created_networks']
            
            # 2. Pre-asignar IPs para TODAS las VMs antes de crear cualquiera
            logger.info("📋 Pre-asignando IPs para todas las VMs...")
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                has_internet = vm_config.get('internet_access', False)
                network_type = 'trunk' if has_internet else 'data'
                
                pre_assigned_ip = self.pre_allocate_vm_ip(vm_config, network_type, slice_id)
                if pre_assigned_ip:
                    ip_assignments[vm_name] = {
                        'ip': pre_assigned_ip,
                        'network_type': network_type,
                        'has_internet': has_internet
                    }
                    logger.info(f"📍 {vm_name}: {pre_assigned_ip} ({network_type})")
                else:
                    error_msg = f"Failed to pre-assign IP for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 3. Crear VMs con IPs pre-asignadas
            logger.info("🔨 Creando VMs con IPs fijas...")
            for vm_config in slice_config.get('nodes', []):
                vm_name = vm_config['name']
                
                if vm_name not in placement:
                    error_msg = f"No placement found for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                
                if vm_name not in ip_assignments:
                    error_msg = f"No IP pre-assigned for VM {vm_name}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    continue
                
                server_assignment = placement[vm_name]
                server_name = server_assignment['hostname']
                ip_info = ip_assignments[vm_name]
                
                try:
                    # Usar el método mejorado con IP fija
                    vm_result = self.create_vm_with_fixed_ip(
                        vm_config, server_name, slice_id, created_networks
                    )
                    
                    # Añadir información de IP
                    vm_result['pre_assigned_ip'] = ip_info['ip']
                    vm_result['network_type'] = ip_info['network_type']
                    vm_result['has_internet'] = ip_info['has_internet']
                    
                    deployed_vms.append(vm_result)
                    logger.info(f"✅ VM {vm_name} deployed with fixed IP {ip_info['ip']}")
                    
                except Exception as e:
                    error_msg = f"Failed to deploy VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    
                    # Liberar IP en caso de error
                    self._release_ip(ip_info['ip'], ip_info['network_type'])
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'ip_assignments': ip_assignments,
                'errors': errors,
                'enhancement_summary': {
                    'pre_assigned_ips': len(ip_assignments),
                    'successful_deployments': len(deployed_vms),
                    'internet_enabled_vms': len([vm for vm in deployed_vms if vm.get('has_internet')]),
                    'fixed_ip_assignments': len([vm for vm in deployed_vms if vm.get('ip_assignment') == 'fixed'])
                }
            }
            
        except Exception as e:
            logger.error(f"Critical error in enhanced deployment: {e}")
            
            # Cleanup IPs en caso de error crítico
            for vm_name, ip_info in ip_assignments.items():
                self._release_ip(ip_info['ip'], ip_info['network_type'])
            
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }
    
    def _get_service_token(self):
        """Obtiene token de autenticación para comunicación entre servicios"""
        try:
            import requests
            response = requests.post(
                "http://localhost:5001/login",
                json={"username": "testuser", "password": "testpass123"},
                timeout=10
            )
            if response.status_code == 200:
                token = response.json().get("token")
                logger.info("✓ Token de servicio obtenido para Network Service")
                return token
            else:
                logger.error(f"Error obteniendo token de servicio: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Excepción obteniendo token de servicio: {e}")
            return None

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

    def setup_slice_networks(self, slice_config: Dict, slice_id: str) -> Dict:
        """
        Configura todas las redes del slice según R5
        
        Args:
            slice_config: Configuración del slice
            slice_id: ID del slice
            
        Returns:
            Dict con información de redes creadas
        """
        created_networks = []
        errors = []
        
        try:
            logger.info(f"Setting up networks for slice {slice_id}")
            
            for network in slice_config.get('networks', []):
                try:
                    network_result = self._create_r5_network(network, slice_id)
                    created_networks.append(network_result)
                    logger.info(f"✓ Network {network['name']} configured")
                except Exception as e:
                    error_msg = f"Failed to create network {network['name']}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            return {
                'success': len(errors) == 0,
                'created_networks': created_networks,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Critical error setting up networks: {e}")
            return {
                'success': False,
                'created_networks': created_networks,
                'errors': [str(e)]
            }

    
    def _create_r5_network(self, network_config: Dict, slice_id: str) -> Dict:
        """Crea una red específica según tipo R5 con nombres cortos"""
        # USAR NOMBRE CORTO - solo los últimos 8 chars del slice_id + tipo
        short_slice_id = slice_id[-8:]  # ej: ac8282
        network_type = network_config.get('network_type', 'data')
        
        # Nombre corto: ej "ac8282-ext" (10 chars)
        network_name = f"{short_slice_id}-{network_type[:3]}"
        
        if network_type not in self.network_config:
            raise ValueError(f"Unsupported network type: {network_type}")
        
        type_config = self.network_config[network_type]
        
        # Configuración específica por tipo
        if network_type == 'management':
            return self._create_management_network(network_config, network_name, type_config)
        elif network_type == 'trunk':
            return self._create_trunk_network_integrated(network_config, network_name, type_config, slice_id)
        elif network_type == 'data':
            return self._create_data_network_integrated(network_config, network_name, type_config, slice_id)
        elif network_type == 'provider':
            return self._create_provider_network_integrated(network_config, network_name, type_config, slice_id)
        else:
            raise ValueError(f"Network type {network_type} not implemented")

    
    def _configure_ovs_trunk_integration(self, bridge: str, vlan_id: int, name: str, config: Dict):
        """Configura VLAN trunk con nombres cortos - CORREGIDO"""
        try:
            # USAR NOMBRE CORTO para la interfaz
            vlan_interface = f"vlan{vlan_id}"  # ej: vlan103 (7 chars)
            
            ovs_commands = [
                # 1. Eliminar interfaz si existe (cleanup)
                f"ovs-vsctl --if-exists del-port {bridge} {vlan_interface}",
                
                # 2. Crear puerto VLAN con nombre corto
                f"ovs-vsctl add-port {bridge} {vlan_interface} tag={vlan_id}",
                
                # 3. Configurar como puerto interno
                f"ovs-vsctl set interface {vlan_interface} type=internal",
                
                # 4. Configurar MTU
                f"ip link set {vlan_interface} mtu 1500",
                
                # 5. Activar interfaz
                f"ip link set {vlan_interface} up",
                
                # 6. Configurar IP del gateway
                f"ip addr add {config.get('gateway', '10.60.1.1')}/24 dev {vlan_interface}",
                
                # 7. Habilitar forwarding
                f"sudo /usr/local/bin/configure-forwarding.sh {vlan_interface}"
            ]
            
            self._execute_ovs_commands(ovs_commands, "trunk network")
            logger.info(f"✓ OVS trunk network {vlan_interface} configured with VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring OVS trunk integration: {e}")
            raise

    def _configure_ovs_data_integration(self, bridge: str, vlan_id: int, name: str, config: Dict):
        """Configura VLAN de datos con integración Network Service"""
        try:
            ovs_commands = [
                # Crear puerto data VLAN
                f"ovs-vsctl add-port {bridge} {name} tag={vlan_id}",
                
                # Configurar como puerto interno
                f"ovs-vsctl set interface {name} type=internal",
                
                # Configurar MTU estándar
                f"ip link set {name} mtu 1500",
                
                # Activar interfaz
                f"ip link set {name} up",
                
                # Configurar IP del gateway si se especifica
                f"ip addr add {config.get('gateway', '192.168.100.1')}/24 dev {name}" if config.get('gateway') else "",
                
                # NO habilitar forwarding (red aislada)
                f"echo 0 > /proc/sys/net/ipv4/conf/{name}/forwarding"
            ]
            
            # Filtrar comandos vacíos
            ovs_commands = [cmd for cmd in ovs_commands if cmd]
            
            self._execute_ovs_commands(ovs_commands, "data network")
            logger.info(f"✓ OVS data network {name} configured with VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring OVS data integration: {e}")
            raise

    def _configure_ovs_provider_integration(self, bridge: str, vlan_id: int, name: str, config: Dict):
        """Configura red provider con capacidades completas"""
        try:
            ovs_commands = [
                # Crear puerto provider con configuración avanzada
                f"ovs-vsctl add-port {bridge} {name} tag={vlan_id}",
                
                # Configurar como puerto provider
                f"ovs-vsctl set interface {name} type=internal",
                f"ovs-vsctl set port {name} vlan_mode=access",
                
                # Configurar MTU jumbo frames si se solicita
                f"ip link set {name} mtu {config.get('mtu', 1500)}",
                
                # Activar interfaz
                f"ip link set {name} up",
                
                # Configurar IP del gateway provider
                f"ip addr add {config.get('gateway', '10.60.1.1')}/24 dev {name}",
                
                # Habilitar forwarding completo
                f"echo 1 > /proc/sys/net/ipv4/conf/{name}/forwarding",
                f"echo 1 > /proc/sys/net/ipv4/conf/{name}/proxy_arp",
                
                # Configurar como provider bridge
                f"ovs-vsctl set bridge {bridge} other-config:forward-bpdu=true",
                
                # Configurar spanning tree si es necesario
                f"ovs-vsctl set bridge {bridge} stp_enable=true" if config.get('stp_enable') else ""
            ]
            
            # Filtrar comandos vacíos
            ovs_commands = [cmd for cmd in ovs_commands if cmd]
            
            self._execute_ovs_commands(ovs_commands, "provider network")
            
            # Configuración adicional para provider networks
            self._configure_provider_nat_rules(vlan_id, config['cidr'])
            
            logger.info(f"✓ OVS provider network {name} configured with VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring OVS provider integration: {e}")
            raise

    def _execute_ovs_commands(self, commands: List[str], network_type: str):
        """Ejecuta comandos OVS en todos los servidores del cluster"""
        try:
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in commands:
                    if not cmd:  # Saltar comandos vacíos
                        continue
                        
                    ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                            f'ubuntu@{server_ip}', f'sudo {cmd}']
                    try:
                        result = subprocess.run(ssh_cmd, check=True, capture_output=True, 
                                            timeout=30, text=True)
                        logger.debug(f"✓ {server_name}: {cmd}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"✗ {server_name}: {cmd} - {e.stderr}")
                        # No fallar por comandos individuales
            
            logger.info(f"OVS commands executed for {network_type}")
            
        except Exception as e:
            logger.error(f"Error executing OVS commands: {e}")
            raise

    def _generate_internet_security_rules(self, cidr: str) -> List[Dict]:
        """Genera reglas de seguridad para redes con acceso a internet"""
        return [
            {
                'rule_type': 'egress',
                'protocol': 'tcp',
                'port_range_min': 80,
                'port_range_max': 80,
                'destination_cidr': '0.0.0.0/0',
                'action': 'allow',
                'priority': 100,
                'description': 'Allow HTTP outbound'
            },
            {
                'rule_type': 'egress',
                'protocol': 'tcp',
                'port_range_min': 443,
                'port_range_max': 443,
                'destination_cidr': '0.0.0.0/0',
                'action': 'allow',
                'priority': 100,
                'description': 'Allow HTTPS outbound'
            },
            {
                'rule_type': 'egress',
                'protocol': 'udp',
                'port_range_min': 53,
                'port_range_max': 53,
                'destination_cidr': '0.0.0.0/0',
                'action': 'allow',
                'priority': 100,
                'description': 'Allow DNS outbound'
            },
            {
                'rule_type': 'ingress',
                'protocol': 'any',
                'source_cidr': cidr,
                'action': 'allow',
                'priority': 200,
                'description': 'Allow intra-network traffic'
            }
        ]

    def _generate_data_security_rules(self, cidr: str) -> List[Dict]:
        """Genera reglas de seguridad para redes de datos (aisladas)"""
        return [
            {
                'rule_type': 'ingress',
                'protocol': 'any',
                'source_cidr': cidr,
                'action': 'allow',
                'priority': 200,
                'description': 'Allow intra-network traffic only'
            },
            {
                'rule_type': 'egress',
                'protocol': 'any',
                'destination_cidr': cidr,
                'action': 'allow',
                'priority': 200,
                'description': 'Allow intra-network traffic only'
            },
            {
                'rule_type': 'egress',
                'protocol': 'any',
                'destination_cidr': '0.0.0.0/0',
                'action': 'deny',
                'priority': 50,
                'description': 'Block external access'
            }
        ]

    def _generate_provider_security_rules(self, config: Dict) -> List[Dict]:
        """Genera reglas de seguridad para redes provider"""
        rules = [
            # Acceso completo dentro de la red
            {
                'rule_type': 'ingress',
                'protocol': 'any',
                'source_cidr': config['cidr'],
                'action': 'allow',
                'priority': 300,
                'description': 'Allow full intra-provider traffic'
            },
            # Acceso completo a internet
            {
                'rule_type': 'egress',
                'protocol': 'any',
                'destination_cidr': '0.0.0.0/0',
                'action': 'allow',
                'priority': 200,
                'description': 'Allow all outbound traffic'
            }
        ]
        
        # Agregar reglas personalizadas si existen
        if 'security_rules' in config:
            rules.extend(config['security_rules'])
        
        return rules

    def _configure_provider_routing(self, vlan_id: int, cidr: str, network_result: Dict):
        """Configura routing avanzado para redes provider"""
        try:
            provider_commands = [
                # Crear tabla de routing provider
                f"ip rule add from {cidr} table provider priority 100",
                
                # Configurar rutas provider
                f"ip route add default via 10.60.1.1 dev vlan{vlan_id} table provider",
                f"ip route add {cidr} dev vlan{vlan_id} table provider",
                
                # Configurar SNAT para provider network
                f"iptables -t nat -A POSTROUTING -s {cidr} -o ens3 -j MASQUERADE",
                
                # Permitir forwarding provider
                f"iptables -A FORWARD -s {cidr} -j ACCEPT",
                f"iptables -A FORWARD -d {cidr} -j ACCEPT",
                
                # Configurar marcado de paquetes para QoS
                f"iptables -t mangle -A PREROUTING -s {cidr} -j MARK --set-mark {vlan_id}"
            ]
            
            # Ejecutar en servidor gateway
            gateway_server = 'server1'
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in provider_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Provider routing command failed: {cmd} - {e.stderr}")
            
            logger.info(f"✓ Provider routing configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring provider routing: {e}")
            raise

    def _configure_provider_qos(self, vlan_id: int, qos_config: Dict):
        """Configura QoS para redes provider"""
        try:
            qos_commands = [
                # Configurar rate limiting
                f"ovs-vsctl set interface vlan{vlan_id} ingress_policing_rate={qos_config.get('rate_limit', 1000000)}",
                f"ovs-vsctl set interface vlan{vlan_id} ingress_policing_burst={qos_config.get('burst_limit', 100000)}",
                
                # Configurar prioridad de tráfico
                f"tc qdisc add dev vlan{vlan_id} root handle 1: htb default 30",
                f"tc class add dev vlan{vlan_id} parent 1: classid 1:1 htb rate {qos_config.get('guaranteed_rate', '100mbit')}",
                f"tc class add dev vlan{vlan_id} parent 1:1 classid 1:10 htb rate {qos_config.get('high_priority_rate', '50mbit')} ceil {qos_config.get('max_rate', '1gbit')}"
            ]
            
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in qos_commands:
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo {cmd}']
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"QoS command failed on {server_name}: {e.stderr}")
            
            logger.info(f"✓ QoS configured for provider VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring provider QoS: {e}")
            raise

    def _configure_provider_nat_rules(self, vlan_id: int, cidr: str):
        """Configura reglas NAT específicas para provider networks"""
        try:
            nat_commands = [
                # SNAT para salida a internet
                f"iptables -t nat -A POSTROUTING -s {cidr} -o ens3 -j MASQUERADE",
                
                # DNAT para servicios entrantes (si se configura)
                # f"iptables -t nat -A PREROUTING -i ens3 -p tcp --dport 8080 -j DNAT --to {cidr_gateway}:80",
                
                # Permitir establecimiento de conexiones
                f"iptables -A FORWARD -s {cidr} -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT",
                f"iptables -A FORWARD -d {cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            ]
            
            gateway_server = 'server1'
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in nat_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"NAT command failed: {cmd} - {e.stderr}")
            
            logger.info(f"✓ NAT rules configured for provider VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring provider NAT: {e}")
            raise        

    def _create_trunk_network_integrated(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red trunk usando Network Service"""
        try:
            network_id = str(uuid.uuid4())
            
            # 1. Crear red en Network Service
            network_service_config = {
                'name': name,
                'cidr': config['cidr'],
                'infrastructure': 'linux',
                'slice_id': slice_id,
                'network_type': 'trunk',
                'gateway': config.get('gateway'),
                'dns_servers': config.get('dns_servers', ['8.8.8.8', '8.8.4.4']),
                'is_external': config.get('internet_access', False),
                'is_provider': False,
                'configure_openflow': True
            }
            
            network_result = self.network_client.create_provider_network(network_service_config)
            vlan_id = network_result.get('vlan_id')
            
            if not vlan_id:
                raise Exception("Network Service did not assign VLAN")
            
            # 2. Configurar OVS localmente
            self._configure_ovs_trunk_integration(type_config['bridge'], vlan_id, name, config)
            
            # 3. Configurar reglas de seguridad si es trunk con internet
            if config.get('internet_access', False):
                security_rules = self._generate_internet_security_rules(config['cidr'])
                self.network_client.configure_security_rules(network_result['id'], security_rules)
                
                # Configurar routing local para internet
                self._configure_internet_access_integrated(vlan_id, config['cidr'])
            
            return {
                'id': network_result['id'],
                'name': name,
                'type': 'trunk',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': config.get('internet_access', False),
                'network_service_managed': True,
                'status': 'active'
            }
            
        except Exception as e:
            logger.error(f"Error creating integrated trunk network: {e}")
            raise

    def _create_data_network_integrated(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red de datos usando Network Service"""
        try:
            network_id = str(uuid.uuid4())
            
            # 1. Crear red en Network Service
            network_service_config = {
                'name': name,
                'cidr': config['cidr'],
                'infrastructure': 'linux',
                'slice_id': slice_id,
                'network_type': 'data',
                'gateway': config.get('gateway'),
                'dns_servers': config.get('dns_servers', ['8.8.8.8']),
                'is_external': False,
                'is_provider': False,
                'configure_openflow': True
            }
            
            network_result = self.network_client.create_provider_network(network_service_config)
            vlan_id = network_result.get('vlan_id')
            
            if not vlan_id:
                raise Exception("Network Service did not assign VLAN")
            
            # 2. Configurar OVS localmente
            self._configure_ovs_data_integration(type_config['bridge'], vlan_id, name, config)
            
            # 3. Configurar reglas de seguridad para red de datos
            security_rules = self._generate_data_security_rules(config['cidr'])
            self.network_client.configure_security_rules(network_result['id'], security_rules)
            
            return {
                'id': network_result['id'],
                'name': name,
                'type': 'data',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': False,
                'network_service_managed': True,
                'status': 'active'
            }
            
        except Exception as e:
            logger.error(f"Error creating integrated data network: {e}")
            raise

    def _create_provider_network_integrated(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red provider completa usando Network Service"""
        try:
            network_id = str(uuid.uuid4())
            
            # 1. Crear red provider en Network Service
            network_service_config = {
                'name': name,
                'cidr': config['cidr'],
                'infrastructure': 'linux',
                'slice_id': slice_id,
                'network_type': 'provider',
                'gateway': config.get('gateway'),
                'dns_servers': config.get('dns_servers', ['8.8.8.8', '1.1.1.1']),
                'is_external': True,      # Provider networks tienen acceso externo
                'is_provider': True,      # Marcar como provider
                'configure_openflow': True,
                'security_groups': config.get('security_groups', [])
            }
            
            network_result = self.network_client.create_provider_network(network_service_config)
            vlan_id = network_result.get('vlan_id')
            
            if not vlan_id:
                raise Exception("Network Service did not assign provider VLAN")
            
            # 2. Configurar OVS como provider network
            self._configure_ovs_provider_integration(type_config['bridge'], vlan_id, name, config)
            
            # 3. Configurar reglas de seguridad avanzadas para provider
            security_rules = self._generate_provider_security_rules(config)
            self.network_client.configure_security_rules(network_result['id'], security_rules)
            
            # 4. Configurar routing provider especial
            self._configure_provider_routing(vlan_id, config['cidr'], network_result)
            
            # 5. Configurar QoS si se especifica
            if 'qos' in config:
                self._configure_provider_qos(vlan_id, config['qos'])
            
            return {
                'id': network_result['id'],
                'name': name,
                'type': 'provider',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': True,
                'is_provider': True,
                'network_service_managed': True,
                'external_access': True,
                'status': 'active'
            }
            
        except Exception as e:
            logger.error(f"Error creating integrated provider network: {e}")
            raise
            
    def create_vm(self, vm_config: Dict, server_name: str, 
              slice_id: str = None, networks: List[Dict] = None) -> Dict:
        """
        Crea una VM en el servidor especificado
        """
        conn = None
        try:
            logger.info(f"Creating VM {vm_config['name']} on server {server_name}")
            logger.debug(f"VM config: {vm_config}")
            logger.debug(f"Available hypervisors: {list(self.hypervisors.keys())}")
            
            # Verificar que el servidor existe
            if server_name not in self.hypervisors:
                available_servers = list(self.hypervisors.keys())
                raise ValueError(f"Unknown server '{server_name}'. Available servers: {available_servers}")
            
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
            logger.error(f"Failed to create VM {vm_config['name']} on {server_name}: {e}")
            logger.error(f"Exception type: {type(e)}")
            logger.error(f"Exception args: {e.args}")
            
            # Cleanup en caso de error
            try:
                self._cleanup_failed_vm(vm_config['name'], server_name)
            except Exception as cleanup_error:
                logger.warning(f"Cleanup failed: {cleanup_error}")
            
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

    def stop_vm(self, vm_name: str, server_name: str) -> bool:
        """Para una VM sin eliminarla"""
        try:
            conn = self.get_connection(server_name)
            
            try:
                domain = conn.lookupByName(vm_name)
            except libvirt.libvirtError:
                logger.warning(f"VM {vm_name} not found on {server_name}")
                return True  # Ya está parada
            
            # Parar la VM si está corriendo
            if domain.isActive():
                logger.info(f"Stopping VM {vm_name}")
                domain.shutdown()  # Graceful shutdown
                
                # Esperar a que pare gracefully
                timeout = 30
                while timeout > 0 and domain.isActive():
                    time.sleep(1)
                    timeout -= 1
                
                # Si no paró gracefully, forzar
                if domain.isActive():
                    logger.warning(f"Force stopping VM {vm_name}")
                    domain.destroy()  # Force shutdown
            
            logger.info(f"✓ VM {vm_name} stopped on {server_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop VM {vm_name}: {e}")
            return False

    def start_vm(self, vm_name: str, server_name: str) -> bool:
        """Inicia una VM parada"""
        try:
            conn = self.get_connection(server_name)
            
            try:
                domain = conn.lookupByName(vm_name)
            except libvirt.libvirtError:
                logger.error(f"VM {vm_name} not found on {server_name}")
                return False
            
            # Iniciar la VM si no está corriendo
            if not domain.isActive():
                logger.info(f"Starting VM {vm_name}")
                domain.create()
                
                # Esperar a que arranque
                self._wait_for_vm_boot(domain, timeout=60)
            
            logger.info(f"✓ VM {vm_name} started on {server_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start VM {vm_name}: {e}")
            return False    
    
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """Despliega slice con soporte completo R5"""
        deployed_vms = []
        created_networks = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            logger.info(f"Deploying slice {slice_id} with R5 network support")
            
            # 1. Configurar redes R5 PRIMERO
            network_result = self.setup_slice_networks(slice_config, slice_id)
            if not network_result['success']:
                errors.extend(network_result['errors'])
            created_networks = network_result['created_networks']
            
            # NUEVO: Extraer mapeo de VLANs para cleanup futuro
            vlan_mapping = {}
            for network in created_networks:
                if network.get('vlan_id'):
                    vlan_mapping[network['name']] = {
                        'vlan_id': network['vlan_id'],
                        'network_type': network.get('type', 'data'),
                        'bridge': network.get('bridge', 'ovs1')
                    }
            
            # 2. Crear VMs con configuración de red R5
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
                    # Preparar configuración con campos R5
                    driver_vm_config = {
                        'name': vm_name,
                        'cpu': vm_config.get('cpu', 1),
                        'ram': vm_config.get('ram', 1024),
                        'disk': vm_config.get('disk', 10),
                        'image': vm_config.get('image', 'ubuntu-20.04'),
                        'internet_access': vm_config.get('internet_access', False),
                        'management_ip': vm_config.get('management_ip')
                    }
                    
                    vm_result = self.create_vm(
                        driver_vm_config, 
                        server_name, 
                        slice_id, 
                        created_networks  # ← Redes R5 configuradas
                    )
                    
                    deployed_vms.append(vm_result)
                    logger.info(f"✓ VM {vm_name} deployed with R5 networking")
                    
                except Exception as e:
                    error_msg = f"Failed to deploy VM {vm_name}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # 3. Configurar routing entre redes si es necesario
            if created_networks:
                try:
                    self._configure_inter_network_routing(created_networks, slice_id)
                except Exception as e:
                    logger.warning(f"Inter-network routing configuration failed: {e}")
                    errors.append(f"Routing configuration: {e}")
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'vlan_mapping': vlan_mapping,
                'errors': errors,
                'r5_summary': {
                    'total_vms': len(slice_config.get('nodes', [])),
                    'deployed_vms': len(deployed_vms),
                    'total_networks': len(slice_config.get('networks', [])),
                    'created_networks': len(created_networks),
                    'network_types': list(set([n.get('type', 'data') for n in created_networks])),
                    'internet_enabled_vms': len([vm for vm in slice_config.get('nodes', []) if vm.get('internet_access')]),
                    'deployment_time': datetime.utcnow().isoformat(),
                    'vlans_allocated': list(vlan_mapping.values())
                }
            }
            
        except Exception as e:
            logger.error(f"Critical error deploying slice {slice_id} with R5: {e}")
            
            # Cleanup en caso de error crítico
            self._cleanup_slice_deployment(deployed_vms, created_networks)
            
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deployed_vms': deployed_vms,
                'created_networks': created_networks
            }

    def _configure_inter_network_routing(self, networks: List[Dict], slice_id: str):
        """Configura routing entre diferentes tipos de red"""
        try:
            management_nets = [n for n in networks if n.get('type') == 'management']
            trunk_nets = [n for n in networks if n.get('type') == 'trunk']
            data_nets = [n for n in networks if n.get('type') == 'data']
            
            # Configurar routing management -> trunk para VMs con internet
            for mgmt_net in management_nets:
                for trunk_net in trunk_nets:
                    if trunk_net.get('internet_access'):
                        self._setup_routing_rule(mgmt_net, trunk_net, 'internet_gateway')
            
            # Configurar routing entre data networks si es necesario
            for i, data_net1 in enumerate(data_nets):
                for data_net2 in data_nets[i+1:]:
                    self._setup_routing_rule(data_net1, data_net2, 'inter_data')
            
            logger.info(f"Inter-network routing configured for slice {slice_id}")
            
        except Exception as e:
            logger.error(f"Error configuring inter-network routing: {e}")
            raise

    def _setup_routing_rule(self, network1: Dict, network2: Dict, rule_type: str):
        """Configura regla de routing específica entre dos redes"""
        try:
            if rule_type == 'internet_gateway':
                # Routing para acceso a internet
                gateway_commands = [
                    f"ip route add {network1['cidr']} via {network2['gateway']} dev {network2['name']}",
                    f"iptables -A FORWARD -s {network1['cidr']} -d {network2['cidr']} -j ACCEPT"
                ]
            elif rule_type == 'inter_data':
                # Routing entre redes de datos
                gateway_commands = [
                    f"ip route add {network2['cidr']} dev {network1['name']}",
                    f"ip route add {network1['cidr']} dev {network2['name']}"
                ]
            else:
                return
            
            # Ejecutar en servidor gateway
            gateway_server = 'server1'
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in gateway_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Routing command failed: {cmd} - {e.stderr}")
            
        except Exception as e:
            logger.error(f"Error setting up routing rule: {e}")
            raise
    
    def destroy_slice(self, slice_id: str, vm_list: List[Dict], deployment_data: Dict = None) -> Dict:
        """Elimina un slice completo con cleanup preciso de VLANs"""
        deleted_vms = []
        errors = []
        
        try:
            logger.info(f"Destroying slice {slice_id} with precise VLAN cleanup")
            
            # NUEVO: Extraer información de VLANs del deployment_data
            vlan_mapping = {}
            if deployment_data:
                # Opción 1: Si viene en deployment_data directamente
                vlan_mapping = deployment_data.get('vlan_mapping', {})
                
                # Opción 2: Si viene en created_networks
                if not vlan_mapping and 'created_networks' in deployment_data:
                    for network in deployment_data['created_networks']:
                        if network.get('vlan_id'):
                            vlan_mapping[network['name']] = {
                                'vlan_id': network['vlan_id'],
                                'network_type': network.get('type', 'data'),
                                'bridge': network.get('bridge', 'ovs1')
                            }
            
            logger.info(f"Found {len(vlan_mapping)} VLANs to cleanup: {list(vlan_mapping.keys()) if vlan_mapping else 'None'}")
            
            # 1. Eliminar VMs primero
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
            
            # 2. MEJORADO: Cleanup preciso de OVS usando VLAN mapping
            ovs_cleanup_success = False
            try:
                if vlan_mapping:
                    logger.info(f"Using precise VLAN cleanup for {len(vlan_mapping)} VLANs")
                    self._cleanup_slice_vlans_precise(slice_id, vlan_mapping)
                    ovs_cleanup_success = True
                else:
                    logger.warning(f"No VLAN mapping available, using fallback cleanup")
                    self._cleanup_slice_ovs_config_fallback(slice_id)
                    ovs_cleanup_success = True
                    
            except Exception as e:
                error_msg = f"OVS cleanup error: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
            
            # 3. Cleanup de redes usando Network Service
            vlan_release_success = False
            try:
                vlan_release_success = self.network_client.release_slice_vlans(slice_id)
                if vlan_release_success:
                    logger.info(f"✓ VLANs released for slice {slice_id}")
                else:
                    errors.append("Failed to release VLANs from Network Service")
                    
            except Exception as e:
                error_msg = f"Network Service VLAN cleanup error: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
            
            # 4. Cleanup routing rules
            routing_cleanup_success = False
            try:
                if vlan_mapping:
                    # Cleanup específico por VLAN
                    self._cleanup_slice_routing_precise(slice_id, vlan_mapping)
                else:
                    # Cleanup general
                    self._cleanup_slice_routing(slice_id)
                routing_cleanup_success = True
                
            except Exception as e:
                error_msg = f"Routing cleanup error: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
            
            return {
                'slice_id': slice_id,
                'status': 'success' if not errors else 'partial',
                'deleted_vms': deleted_vms,
                'errors': errors,
                'cleanup_summary': {
                    'vms_deleted': len(deleted_vms),
                    'vlans_cleaned': len(vlan_mapping),
                    'vlans_released': vlan_release_success,
                    'ovs_cleaned': ovs_cleanup_success,
                    'routing_cleaned': routing_cleanup_success,
                    'cleanup_method': 'precise' if vlan_mapping else 'fallback',
                    'networks_found': list(vlan_mapping.keys()) if vlan_mapping else []
                }
            }
            
        except Exception as e:
            logger.error(f"Critical error destroying slice {slice_id}: {e}")
            return {
                'slice_id': slice_id,
                'status': 'failed',
                'error': str(e),
                'deleted_vms': deleted_vms
            }

    def _cleanup_slice_vlans_precise(self, slice_id: str, vlan_mapping: Dict):
        """Cleanup preciso usando mapeo de VLANs específicas"""
        try:
            cleanup_commands = []
            
            # Cleanup específico para cada VLAN del slice
            for network_name, vlan_info in vlan_mapping.items():
                vlan_id = vlan_info['vlan_id']
                bridge = vlan_info.get('bridge', 'ovs1')
                network_type = vlan_info.get('network_type', 'data')
                
                logger.info(f"Cleaning VLAN {vlan_id} ({network_type}) for network {network_name}")
                
                # Eliminar puertos VLAN específicos
                cleanup_commands.extend([
                    f"ovs-vsctl del-port {bridge} vlan{vlan_id} 2>/dev/null || true",
                    f"ovs-vsctl del-port {bridge} gw-vlan{vlan_id} 2>/dev/null || true",
                    
                    # Eliminar interfaces del sistema
                    f"ip link delete vlan{vlan_id} 2>/dev/null || true",
                    f"ip link delete gw-vlan{vlan_id} 2>/dev/null || true",
                    
                    # Limpiar flows de OpenFlow específicos
                    f"ovs-ofctl del-flows {bridge} 'dl_vlan={vlan_id}' 2>/dev/null || true",
                    
                    # Limpiar reglas de routing específicas
                    f"ip route del table {200 + vlan_id} 2>/dev/null || true",
                    f"ip rule del table {200 + vlan_id} 2>/dev/null || true",
                    
                    # Limpiar reglas iptables específicas de la VLAN
                    f"iptables -t nat -D POSTROUTING -s 10.60.1.0/24 -o ens3 -j MASQUERADE 2>/dev/null || true",
                    f"iptables -D FORWARD -i vlan{vlan_id} -j ACCEPT 2>/dev/null || true",
                    f"iptables -D FORWARD -o vlan{vlan_id} -j ACCEPT 2>/dev/null || true"
                ])
            
            # Cleanup general del slice (interfaces con nombres de slice)
            slice_short_id = slice_id[-8:]
            cleanup_commands.extend([
                f"for port in $(ovs-vsctl list-ports ovs1 | grep -E '{slice_short_id}'); do ovs-vsctl del-port ovs1 $port 2>/dev/null || true; done",
                f"ovs-ofctl del-flows ovs1 'cookie={slice_id}/-1' 2>/dev/null || true"
            ])
            
            # Ejecutar comandos en todos los servidores
            self._execute_ovs_commands(cleanup_commands, f"precise cleanup for slice {slice_id}")
            
            logger.info(f"✓ Precise VLAN cleanup completed for slice {slice_id}: cleaned {len(vlan_mapping)} VLANs")
            
        except Exception as e:
            logger.error(f"Error in precise VLAN cleanup: {e}")
            raise

    def _cleanup_slice_ovs_config_fallback(self, slice_id: str):
        """Cleanup fallback cuando no hay información específica de VLANs"""
        try:
            logger.info(f"Using fallback cleanup method for slice {slice_id}")
            
            slice_short_id = slice_id[-8:]
            
            cleanup_commands = [
                # Buscar puertos con el ID del slice
                f"for port in $(ovs-vsctl list-ports ovs1 | grep -E '{slice_short_id}|{slice_id}'); do ovs-vsctl del-port ovs1 $port 2>/dev/null || true; done",
                
                # Limpiar flows del slice
                f"ovs-ofctl del-flows ovs1 'cookie={slice_id}/-1' 2>/dev/null || true",
                
                # Intentar limpiar interfaces del sistema
                f"for iface in $(ip link show | grep -E '{slice_short_id}|{slice_id}' | cut -d: -f2 | tr -d ' '); do ip link delete $iface 2>/dev/null || true; done"
            ]
            
            self._execute_ovs_commands(cleanup_commands, f"fallback cleanup for slice {slice_id}")
            
            logger.info(f"✓ Fallback cleanup completed for slice {slice_id}")
            
        except Exception as e:
            logger.error(f"Error in fallback cleanup: {e}")
            raise

    def _cleanup_slice_routing_precise(self, slice_id: str, vlan_mapping: Dict):
        """Cleanup preciso de routing usando información específica de VLANs"""
        try:
            routing_cleanup_commands = []
            
            for network_name, vlan_info in vlan_mapping.items():
                vlan_id = vlan_info['vlan_id']
                network_type = vlan_info.get('network_type', 'data')
                
                # Cleanup específico según el tipo de red
                if network_type in ['trunk', 'provider']:
                    # Redes con acceso a internet
                    routing_cleanup_commands.extend([
                        f"ip route del 10.60.1.0/24 table {200 + vlan_id} 2>/dev/null || true",
                        f"ip rule del from 10.60.1.0/24 table {200 + vlan_id} priority {200 + vlan_id} 2>/dev/null || true",
                        f"iptables -t nat -D POSTROUTING -s 10.60.1.0/24 -o ens3 -j MASQUERADE 2>/dev/null || true"
                    ])
            
            # Cleanup general del slice
            routing_cleanup_commands.extend([
                f"iptables-save | grep -v '{slice_id}' | iptables-restore 2>/dev/null || true"
            ])
            
            # Ejecutar en el servidor gateway
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in routing_cleanup_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo bash -c "{cmd}"']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError:
                    pass  # Esperado si la regla no existe
            
            logger.info(f"✓ Precise routing cleanup completed for slice {slice_id}")
            
        except Exception as e:
            logger.error(f"Error in precise routing cleanup: {e}")
            raise

    def _cleanup_slice_ovs_config(self, slice_id: str):
        """Limpia configuración OVS específica del slice"""
        try:
            cleanup_commands = [
                # Buscar y eliminar puertos del slice
                f"for port in $(ovs-vsctl list-ports ovs1 | grep {slice_id}); do ovs-vsctl del-port ovs1 $port; done",
                
                # Limpiar flows específicos del slice
                f"ovs-ofctl del-flows ovs1 'cookie={slice_id}/-1'",
                
                # Limpiar interfaces de red del slice
                f"for iface in $(ip link show | grep {slice_id} | cut -d: -f2); do ip link delete $iface 2>/dev/null || true; done"
            ]
            
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in cleanup_commands:
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo bash -c "{cmd}"']
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        logger.debug(f"OVS cleanup command on {server_name}: {e.stderr}")
            
            logger.info(f"✓ OVS configuration cleaned for slice {slice_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning OVS configuration: {e}")
            raise

    def _cleanup_slice_routing(self, slice_id: str):
        """Limpia reglas de routing específicas del slice"""
        try:
            # Obtener CIDRs del slice desde deployment_data si está disponible
            routing_cleanup_commands = [
                # Limpiar reglas iptables con comentario del slice
                f"iptables-save | grep -v '{slice_id}' | iptables-restore",
                
                # Limpiar rutas específicas del slice
                f"ip route show table provider | grep {slice_id} | while read route; do ip route del $route table provider; done",
                
                # Limpiar reglas de routing policy
                f"ip rule list | grep {slice_id} | while read prio rule; do ip rule del $rule 2>/dev/null || true; done"
            ]
            
            gateway_server = 'server1'
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in routing_cleanup_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', f'sudo bash -c "{cmd}"']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError as e:
                    logger.debug(f"Routing cleanup command: {e.stderr}")
            
            logger.info(f"✓ Routing rules cleaned for slice {slice_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning routing rules: {e}")
            raise

    def validate_network_service_integration(self) -> Dict:
        """Valida que la integración con Network Service funcione correctamente"""
        try:
            validation_result = {
                'network_service_available': False,
                'vlan_allocation_working': False,
                'ovs_bridges_ready': False,
                'routing_configured': False,
                'errors': []
            }
            
            # 1. Verificar conectividad con Network Service
            try:
                response = requests.get(
                    f"{self.network_client.base_url}/health",
                    timeout=10
                )
                if response.status_code == 200:
                    validation_result['network_service_available'] = True
                    logger.info("✓ Network Service is available")
                else:
                    validation_result['errors'].append(f"Network Service unhealthy: {response.status_code}")
            except Exception as e:
                validation_result['errors'].append(f"Cannot connect to Network Service: {e}")
            
            # 2. Verificar OVS bridges en todos los servidores
            ovs_ok = True
            for server_name in self.hypervisors.keys():
                try:
                    server_ip = self.hypervisors[server_name]['ip']
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'sudo ovs-vsctl show']
                    result = subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    
                    if 'ovs1' not in result.stdout.decode():
                        validation_result['errors'].append(f"OVS bridge ovs1 not found on {server_name}")
                        ovs_ok = False
                        
                except Exception as e:
                    validation_result['errors'].append(f"OVS check failed on {server_name}: {e}")
                    ovs_ok = False
            
            validation_result['ovs_bridges_ready'] = ovs_ok
            
            # 3. Verificar routing básico
            try:
                gateway_server = 'server1'
                server_ip = self.hypervisors[gateway_server]['ip']
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'sudo iptables -L -n | grep -q FORWARD']
                subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                validation_result['routing_configured'] = True
                logger.info("✓ Basic routing is configured")
            except Exception as e:
                validation_result['errors'].append(f"Routing check failed: {e}")
            
            # 4. Test de asignación de VLAN (sin crear realmente)
            try:
                # Este sería un test más completo en producción
                validation_result['vlan_allocation_working'] = validation_result['network_service_available']
            except Exception as e:
                validation_result['errors'].append(f"VLAN allocation test failed: {e}")
            
            validation_result['overall_status'] = 'healthy' if not validation_result['errors'] else 'degraded'
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return {
                'overall_status': 'failed',
                'errors': [str(e)]
            }        
    
    # Métodos privados auxiliares
    def _cleanup_internet_access(self, vlan_id: int, cidr: str):
        """Limpia configuración de acceso a internet para una VLAN"""
        try:
            logger.info(f"Cleaning up internet access for VLAN {vlan_id}")
            
            vlan_interface = f"vlan{vlan_id}"
            outbound_interface = 'ens3'
            
            cleanup_commands = [
                # Limpiar reglas NAT
                f"iptables -t nat -D POSTROUTING -s {cidr} -o {outbound_interface} -j MASQUERADE 2>/dev/null || true",
                
                # Limpiar reglas de forwarding
                f"iptables -D FORWARD -s {cidr} -o {outbound_interface} -j ACCEPT 2>/dev/null || true",
                f"iptables -D FORWARD -i {outbound_interface} -d {cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true",
                
                # Limpiar marcado de paquetes
                f"iptables -t mangle -D PREROUTING -s {cidr} -j MARK --set-mark {vlan_id} 2>/dev/null || true",
                
                # Limpiar reglas de firewall específicas
                f"iptables -D FORWARD -s {cidr} -p tcp --dport 80 -j ACCEPT 2>/dev/null || true",
                f"iptables -D FORWARD -s {cidr} -p tcp --dport 443 -j ACCEPT 2>/dev/null || true",
                f"iptables -D FORWARD -s {cidr} -p udp --dport 53 -j ACCEPT 2>/dev/null || true",
                
                # Limpiar rutas
                f"ip route del {cidr} table internet 2>/dev/null || true",
                f"ip rule del from {cidr} table internet 2>/dev/null || true",
                
                # Limpiar QoS
                f"tc qdisc del dev {vlan_interface} root 2>/dev/null || true",
                
                # Limpiar DNS config
                f"rm -f /etc/dnsmasq.d/vlan{vlan_id}.conf",
                f"systemctl is-active dnsmasq && systemctl reload dnsmasq || true"
            ]
            
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in cleanup_commands:
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo bash -c "{cmd}"']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                except subprocess.CalledProcessError:
                    # Es normal que algunos comandos fallen si las reglas no existen
                    pass
            
            logger.info(f"✓ Internet access cleanup completed for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error cleaning up internet access: {e}")
            # No fallar el cleanup general por esto

    def _configure_internet_access_integrated(self, vlan_id: int, cidr: str):
        """
        Configura acceso a internet para una VLAN específica con integración completa
        
        Args:
            vlan_id: ID de la VLAN que tendrá acceso a internet
            cidr: CIDR de la red que tendrá acceso (ej: "10.60.1.100/28")
        """
        try:
            logger.info(f"Configuring internet access for VLAN {vlan_id} with CIDR {cidr}")
            
            # 1. Configurar NAT y masquerading
            self._configure_nat_rules(vlan_id, cidr)
            
            # 2. Configurar reglas de firewall para internet
            self._configure_internet_firewall_rules(vlan_id, cidr)
            
            # 3. Configurar routing para acceso a internet
            self._configure_internet_routing(vlan_id, cidr)
            
            # 4. Configurar DNS forwarding
            self._configure_dns_forwarding(vlan_id, cidr)
            
            # 5. Habilitar IP forwarding si no está habilitado
            self._enable_ip_forwarding()
            
            # 6. Configurar reglas de QoS para internet (opcional)
            self._configure_internet_qos(vlan_id, cidr)
            
            logger.info(f"✓ Internet access configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring internet access for VLAN {vlan_id}: {e}")
            raise

    def _configure_nat_rules(self, vlan_id: int, cidr: str):
        """Configura reglas NAT para salida a internet"""
        try:
            # Determinar interfaz de salida (típicamente la interfaz con acceso a internet)
            outbound_interface = 'ens3'  # Interfaz hacia el gateway/internet
            vlan_interface = f"vlan{vlan_id}"
            
            nat_commands = [
                # SNAT/Masquerading para salida a internet
                f"iptables -t nat -A POSTROUTING -s {cidr} -o {outbound_interface} -j MASQUERADE",
                
                # Permitir forwarding desde la VLAN hacia internet
                f"iptables -A FORWARD -s {cidr} -o {outbound_interface} -j ACCEPT",
                
                # Permitir respuestas de vuelta
                f"iptables -A FORWARD -i {outbound_interface} -d {cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                
                # Marcar paquetes para tracking (útil para QoS y logging)
                f"iptables -t mangle -A PREROUTING -s {cidr} -j MARK --set-mark {vlan_id}",
                
                # Logging opcional para debugging
                f"iptables -A FORWARD -s {cidr} -j LOG --log-prefix 'VLAN{vlan_id}-OUT: ' --log-level 4" if logger.level == logging.DEBUG else ""
            ]
            
            # Filtrar comandos vacíos
            nat_commands = [cmd for cmd in nat_commands if cmd]
            
            # Ejecutar en servidor gateway (el que tiene acceso a internet)
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in nat_commands:
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    result = subprocess.run(ssh_cmd, check=True, capture_output=True, 
                                        timeout=30, text=True)
                    logger.debug(f"✓ NAT rule: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"✗ NAT rule failed: {cmd} - {e.stderr}")
                    # Continuar con otros comandos, algunos pueden fallar si ya existen
            
            logger.info(f"✓ NAT rules configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring NAT rules: {e}")
            raise

    def _configure_internet_firewall_rules(self, vlan_id: int, cidr: str):
        """Configura reglas de firewall específicas para acceso a internet - CORREGIDO"""
        try:
            firewall_commands = [
                # Permitir tráfico HTTP/HTTPS saliente
                f"iptables -A FORWARD -s {cidr} -p tcp --dport 80 -j ACCEPT",
                f"iptables -A FORWARD -s {cidr} -p tcp --dport 443 -j ACCEPT",
                
                # Permitir DNS saliente (UDP y TCP)
                f"iptables -A FORWARD -s {cidr} -p udp --dport 53 -j ACCEPT",
                f"iptables -A FORWARD -s {cidr} -p tcp --dport 53 -j ACCEPT",
                
                # Permitir NTP
                f"iptables -A FORWARD -s {cidr} -p udp --dport 123 -j ACCEPT",
                
                # Permitir SSH saliente
                f"iptables -A FORWARD -s {cidr} -p tcp --dport 22 -j ACCEPT",
                
                # Permitir ICMP
                f"iptables -A FORWARD -s {cidr} -p icmp -j ACCEPT",
                
                # CORREGIR: Bloquear acceso a redes privadas (reglas separadas)
                f"iptables -A FORWARD -s {cidr} -d 192.168.0.0/16 -j DROP",
                f"iptables -A FORWARD -s {cidr} -d 172.16.0.0/12 -j DROP",
                f"iptables -A FORWARD -s {cidr} -d 10.0.0.0/8 -j DROP",
                f"iptables -I FORWARD -s {cidr} -d {cidr} -j ACCEPT",  # Permitir tráfico interno
                
                # Permitir conexiones establecidas
                f"iptables -A FORWARD -d {cidr} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            ]
            
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in firewall_commands:
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    logger.debug(f"✓ Firewall rule: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"✗ Firewall rule failed: {cmd} - {e.stderr}")
            
            logger.info(f"✓ Firewall rules configured for internet access VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring firewall rules: {e}")
            raise

    
    def _configure_internet_routing(self, vlan_id: int, cidr: str):
        """Configura routing específico para acceso a internet - CORREGIDO"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(cidr, strict=False)
            gateway_ip = str(list(network.hosts())[0])  # Primera IP como gateway
            vlan_interface = f"vlan{vlan_id}"
            
            # Usar tabla numérica en lugar de nombre
            table_id = 100 + vlan_id  # Tabla única por VLAN
            
            routing_commands = [
                # NO configurar IP aquí - ya se hizo en OVS setup
                
                # Crear tabla de routing si no existe
                f"echo '{table_id} vlan{vlan_id}' >> /etc/iproute2/rt_tables 2>/dev/null || true",
                
                # Configurar rutas en la tabla específica
                f"ip route add {cidr} dev {vlan_interface} table {table_id}",
                f"ip route add default via 10.60.1.1 table {table_id}",
                
                # Configurar policy routing
                f"ip rule add from {cidr} table {table_id} priority {100 + vlan_id}",
                
                # Flush route cache
                f"ip route flush cache"
            ]
            
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in routing_commands:
                if not cmd:  # Skip empty commands
                    continue
                    
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    logger.debug(f"✓ Routing: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"✗ Routing command failed: {cmd} - {e.stderr}")
            
            logger.info(f"✓ Internet routing configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring internet routing: {e}")
            raise

    def _configure_dns_forwarding(self, vlan_id: int, cidr: str):
        """Configura forwarding de DNS para la red"""
        try:
            dns_commands = [
                # Configurar dnsmasq para esta red (si está instalado)
                f"systemctl is-active dnsmasq && echo 'interface=vlan{vlan_id}' >> /etc/dnsmasq.d/vlan{vlan_id}.conf || true",
                f"systemctl is-active dnsmasq && echo 'dhcp-range=vlan{vlan_id},{cidr.split('/')[0].rsplit('.', 1)[0]}.10,{cidr.split('/')[0].rsplit('.', 1)[0]}.50,12h' >> /etc/dnsmasq.d/vlan{vlan_id}.conf || true",
                f"systemctl is-active dnsmasq && systemctl reload dnsmasq || true",
                
                # Configurar resolv.conf para forwarding
                f"echo 'nameserver 8.8.8.8' > /etc/resolv.conf.vlan{vlan_id}",
                f"echo 'nameserver 1.1.1.1' >> /etc/resolv.conf.vlan{vlan_id}",
                
                # Configurar iptables para permitir DNS forwarding
                f"iptables -A INPUT -i vlan{vlan_id} -p udp --dport 53 -j ACCEPT",
                f"iptables -A INPUT -i vlan{vlan_id} -p tcp --dport 53 -j ACCEPT"
            ]
            
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in dns_commands:
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo bash -c "{cmd}"']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    logger.debug(f"✓ DNS: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.debug(f"DNS command (non-critical): {cmd} - {e.stderr}")
            
            logger.info(f"✓ DNS forwarding configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring DNS forwarding: {e}")
            # No fallar por DNS, es opcional
            pass

    def _enable_ip_forwarding(self):
        """Habilita IP forwarding en el sistema"""
        try:
            forwarding_commands = [
                # Habilitar IP forwarding temporalmente
                "echo 1 > /proc/sys/net/ipv4/ip_forward",
                
                # Hacer permanente el cambio
                "sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf",
                "sed -i 's/net.ipv4.ip_forward=0/net.ipv4.ip_forward=1/' /etc/sysctl.conf",
                
                # Si no existe la línea, agregarla
                "grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
                
                # Aplicar cambios
                "sysctl -p"
            ]
            
            # Aplicar en todos los servidores
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in forwarding_commands:
                    ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                            f'ubuntu@{server_ip}', f'sudo {cmd}']
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        logger.debug(f"IP forwarding command on {server_name}: {e.stderr}")
            
            logger.info("✓ IP forwarding enabled on all servers")
            
        except Exception as e:
            logger.error(f"Error enabling IP forwarding: {e}")
            raise

    def _configure_internet_qos(self, vlan_id: int, cidr: str):
        """Configura QoS para tráfico de internet (opcional)"""
        try:
            vlan_interface = f"vlan{vlan_id}"
            
            qos_commands = [
                # Configurar traffic shaping básico
                f"tc qdisc add dev {vlan_interface} root handle 1: htb default 30",
                
                # Clase principal (100 Mbps por defecto)
                f"tc class add dev {vlan_interface} parent 1: classid 1:1 htb rate 100mbit",
                
                # Clase para tráfico de alta prioridad (50 Mbps garantizado)
                f"tc class add dev {vlan_interface} parent 1:1 classid 1:10 htb rate 50mbit ceil 100mbit",
                
                # Clase para tráfico normal (30 Mbps garantizado)
                f"tc class add dev {vlan_interface} parent 1:1 classid 1:20 htb rate 30mbit ceil 80mbit",
                
                # Clase para tráfico de baja prioridad (20 Mbps garantizado)
                f"tc class add dev {vlan_interface} parent 1:1 classid 1:30 htb rate 20mbit ceil 60mbit",
                
                # Filtros para clasificar tráfico
                f"tc filter add dev {vlan_interface} parent 1: protocol ip prio 1 u32 match ip dport 80 0xffff flowid 1:20",
                f"tc filter add dev {vlan_interface} parent 1: protocol ip prio 1 u32 match ip dport 443 0xffff flowid 1:20",
                f"tc filter add dev {vlan_interface} parent 1: protocol ip prio 1 u32 match ip dport 53 0xffff flowid 1:10",
                f"tc filter add dev {vlan_interface} parent 1: protocol ip prio 2 u32 match ip src {cidr} flowid 1:30"
            ]
            
            gateway_server = self._get_internet_gateway_server()
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in qos_commands:
                ssh_cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', 
                        f'ubuntu@{server_ip}', f'sudo {cmd}']
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    logger.debug(f"✓ QoS: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.debug(f"QoS command (optional): {cmd} - {e.stderr}")
            
            logger.info(f"✓ QoS configured for internet access VLAN {vlan_id}")
            
        except Exception as e:
            logger.warning(f"QoS configuration failed (non-critical): {e}")
            # QoS es opcional, no fallar por esto

    def _get_internet_gateway_server(self) -> str:
        """Determina qué servidor actúa como gateway de internet"""
        # Por defecto, usar server1 como gateway
        # En un entorno real, esto podría determinarse dinámicamente
        gateway_server = 'server1'
        
        # Verificar que el servidor existe
        if gateway_server not in self.hypervisors:
            # Fallback al primer servidor disponible
            gateway_server = list(self.hypervisors.keys())[0]
            logger.warning(f"Using {gateway_server} as internet gateway (fallback)")
        
        return gateway_server

    def _allocate_vlan(self, vlan_range: Tuple[int, int], slice_id: str) -> Optional[int]:
        """Asigna una VLAN del rango especificado"""
        try:
            # Llamar al Network Service para asignar VLAN
            import requests
            
            network_service_url = "http://localhost:5004"  # Network Service
            headers = {'Content-Type': 'application/json'}
            
            # Buscar VLAN disponible en el rango
            for vlan_id in range(vlan_range[0], vlan_range[1] + 1):
                response = requests.post(
                    f"{network_service_url}/api/vlans/{vlan_id}/allocate",
                    json={
                        'infrastructure': 'linux',
                        'slice_id': slice_id,
                        'description': f'VLAN for slice {slice_id}'
                    },
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info(f"Allocated VLAN {vlan_id} for slice {slice_id}")
                    return vlan_id
            
            logger.warning(f"No available VLANs in range {vlan_range}")
            return None
            
        except Exception as e:
            logger.error(f"Error allocating VLAN: {e}")
            return None

    def _configure_ovs_vlan(self, bridge: str, vlan_id: int, network_name: str):
        """Configura VLAN en OVS bridge"""
        try:
            # Comandos OVS para configurar VLAN
            ovs_commands = [
                # Crear puerto VLAN en el bridge
                f"ovs-vsctl add-port {bridge} {network_name} tag={vlan_id}",
                
                # Configurar puerto como internal
                f"ovs-vsctl set interface {network_name} type=internal",
                
                # Configurar MTU
                f"ip link set {network_name} mtu 1500",
                
                # Activar interfaz
                f"ip link set {network_name} up"
            ]
            
            # Ejecutar comandos en todos los servidores del cluster
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in ovs_commands:
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                        logger.debug(f"Executed on {server_name}: {cmd}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Command failed on {server_name}: {cmd} - {e.stderr}")
            
            logger.info(f"OVS VLAN {vlan_id} configured on bridge {bridge}")
            
        except Exception as e:
            logger.error(f"Error configuring OVS VLAN: {e}")
            raise

    def _configure_internet_access(self, vlan_id: int, cidr: str):
        """Configura acceso a internet para una VLAN"""
        try:
            # Configurar NAT y routing para acceso a internet
            gateway_commands = [
                # Configurar NAT para la red
                f"iptables -t nat -A POSTROUTING -s {cidr} -o ens3 -j MASQUERADE",
                
                # Permitir forwarding
                f"iptables -A FORWARD -s {cidr} -j ACCEPT",
                f"iptables -A FORWARD -d {cidr} -j ACCEPT",
                
                # Habilitar IP forwarding
                "echo 1 > /proc/sys/net/ipv4/ip_forward"
            ]
            
            # Ejecutar en el gateway (servidor que tiene acceso a internet)
            gateway_server = 'server1'  # Asumiendo que server1 es el gateway
            server_ip = self.hypervisors[gateway_server]['ip']
            
            for cmd in gateway_commands:
                ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                try:
                    subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    logger.debug(f"Gateway command executed: {cmd}")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Gateway command failed: {cmd} - {e.stderr}")
            
            logger.info(f"Internet access configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring internet access: {e}")
            raise

    def _configure_provider_network(self, vlan_id: int, cidr: str):
        """Configura red provider con capacidades especiales"""
        try:
            # Configurar red provider con acceso directo
            provider_commands = [
                # Configurar bridge para provider network
                f"ovs-vsctl set port vlan{vlan_id} vlan_mode=trunk",
                
                # Configurar QoS si es necesario
                f"ovs-vsctl set interface vlan{vlan_id} ingress_policing_rate=1000000",
                
                # Configurar routing especial para provider
                f"ip route add {cidr} dev vlan{vlan_id} table provider"
            ]
            
            # Ejecutar en todos los servidores
            for server_name in self.hypervisors.keys():
                server_ip = self.hypervisors[server_name]['ip']
                
                for cmd in provider_commands:
                    ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
                    try:
                        subprocess.run(ssh_cmd, check=True, capture_output=True, timeout=30)
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Provider command failed on {server_name}: {e.stderr}")
            
            logger.info(f"Provider network configured for VLAN {vlan_id}")
            
        except Exception as e:
            logger.error(f"Error configuring provider network: {e}")
            raise

    def _create_management_network(self, config: Dict, name: str, type_config: Dict) -> Dict:
        """Crea red de management (sin VLAN)"""
        try:
            # Red de management usa bridge directo, sin VLAN
            return {
                'name': name,
                'type': 'management',
                'cidr': config['cidr'],
                'gateway': config.get('gateway', type_config['gateway']),
                'bridge': type_config['bridge'],
                'vlan_id': None,
                'internet_access': False,
                'status': 'active'
            }
        except Exception as e:
            logger.error(f"Error creating management network: {e}")
            raise

    def _create_trunk_network(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red trunk con VLAN para internet access"""
        try:
            # Asignar VLAN del rango trunk
            vlan_id = self._allocate_vlan(type_config['vlan_range'], slice_id)
            
            if not vlan_id:
                raise Exception("No available VLANs in trunk range")
            
            # Configurar VLAN en OVS
            self._configure_ovs_vlan(type_config['bridge'], vlan_id, name)
            
            # Configurar reglas de internet access si es necesario
            if config.get('internet_access', False):
                self._configure_internet_access(vlan_id, config['cidr'])
            
            return {
                'name': name,
                'type': 'trunk',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': config.get('internet_access', False),
                'status': 'active'
            }
        except Exception as e:
            logger.error(f"Error creating trunk network: {e}")
            raise

    def _create_data_network(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red de datos con VLAN (sin internet)"""
        try:
            # Asignar VLAN del rango data
            vlan_id = self._allocate_vlan(type_config['vlan_range'], slice_id)
            
            if not vlan_id:
                raise Exception("No available VLANs in data range")
            
            # Configurar VLAN en OVS
            self._configure_ovs_vlan(type_config['bridge'], vlan_id, name)
            
            return {
                'name': name,
                'type': 'data',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': False,
                'status': 'active'
            }
        except Exception as e:
            logger.error(f"Error creating data network: {e}")
            raise

    def _create_provider_network(self, config: Dict, name: str, type_config: Dict, slice_id: str) -> Dict:
        """Crea red provider con capacidades avanzadas"""
        try:
            # Asignar VLAN del rango provider
            vlan_id = self._allocate_vlan(type_config['vlan_range'], slice_id)
            
            if not vlan_id:
                raise Exception("No available VLANs in provider range")
            
            # Configurar VLAN en OVS
            self._configure_ovs_vlan(type_config['bridge'], vlan_id, name)
            
            # Configurar como red provider
            self._configure_provider_network(vlan_id, config['cidr'])
            
            return {
                'name': name,
                'type': 'provider',
                'cidr': config['cidr'],
                'gateway': config.get('gateway'),
                'bridge': type_config['bridge'],
                'vlan_id': vlan_id,
                'internet_access': True,
                'is_provider': True,
                'status': 'active'
            }
        except Exception as e:
            logger.error(f"Error creating provider network: {e}")
            raise

    def _cleanup_slice_networks(self, networks: list) -> list:
        errors = []

        for net in networks:
            if not isinstance(net, dict):
                error_msg = f"Invalid network entry (not a dict): {net}"
                logger.error(error_msg)
                errors.append(error_msg)
                continue

            try:
                server_id = net['server_id']
                zone = net['zone']
                network_name = net['name']
            except KeyError as e:
                error_msg = f"Missing key in network definition: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
                continue

            conn = self._connect(server_id, zone)
            try:
                net_obj = conn.networkLookupByName(network_name)
                if net_obj.isActive():
                    net_obj.destroy()
                net_obj.undefine()
                logger.info(f"✓ Deleted network: {network_name} on {server_id}")
            except libvirt.libvirtError as e:
                error_msg = f"Failed to delete network {network_name} on {server_id}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        return errors


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
            disk_path = f"/home/ubuntu/vm-disks/{vm_name}.qcow2"
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

    def _get_used_disk_space(self, server_name: str) -> int:
        """Obtiene espacio de disco usado en GB"""
        try:
            server_hostname = self.hypervisors[server_name]['hostname']
            cmd = [
                'ssh', 
                '-o', 'StrictHostKeyChecking=no',
                f'ubuntu@{server_hostname}', 
                'du', '-s', '/home/ubuntu/vm-images'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Resultado en KB, convertir a GB
            kb_used = int(result.stdout.split()[0])
            gb_used = kb_used // (1024 * 1024)
            
            return gb_used
            
        except Exception as e:
            logger.warning(f"Could not get disk usage for {server_name}: {e}")
            return 0

    def _generate_mac_address(self, vm_name: str, server_name: str) -> str:
        """Genera MAC address única para la VM"""
        # Usar hash del nombre + servidor para generar MAC consistente
        import hashlib
        hash_input = f"{vm_name}-{server_name}".encode()
        hash_value = hashlib.md5(hash_input).hexdigest()
        
        # Formato MAC: 52:54:00:XX:XX:XX (prefijo KVM)
        mac = f"52:54:00:{hash_value[0:2]}:{hash_value[2:4]}:{hash_value[4:6]}"
        return mac

    def _create_slice_network(self, network_config: Dict, slice_id: str) -> Dict:
        """Crea red para el slice"""
        try:
            # Para Linux cluster, las redes se manejan a través de OVS
            # Este método coordina con el network_service
            
            network_name = f"{slice_id}-{network_config['name']}"
            
            logger.info(f"Creating network {network_name} for slice {slice_id}")
            
            # En el cluster Linux, todas las redes usan el mismo bridge OVS
            # pero pueden tener diferentes VLANs o configuraciones
            
            return {
                'name': network_name,
                'cidr': network_config['cidr'],
                'vlan_id': None,  # Se asignaría por el network_service
                'status': 'active',
                'bridge': self.ovs_bridge,
                'gateway': network_config.get('gateway'),
                'dns_servers': network_config.get('dns_servers', ['8.8.8.8'])
            }
            
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            raise Exception(f"Network creation failed: {e}")
    
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
    
    def _cleanup_disk(self, disk_path: str, server_name: str):
        """Elimina archivo de disco"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'rm', '-f', disk_path]
            
            subprocess.run(ssh_cmd, check=True, capture_output=True)
            logger.info(f"Disk removed: {disk_path}")
            
        except Exception as e:
            logger.warning(f"Failed to remove disk {disk_path}: {e}")

    
    def _get_compatible_machine_type(self, server_name: str) -> str:
        """Obtiene un tipo de máquina compatible para el servidor"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            
            # Obtener tipos de máquina disponibles
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'qemu-system-x86_64', '-machine', 'help']
            result = subprocess.run(ssh_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                machine_types = result.stdout
                
                # Prioridad para servidores Ubuntu 20.04 con QEMU 4.2.1
                preferred_types = [
                    'ubuntu',            # Alias para pc-i440fx-focal
                    'pc-i440fx-focal',   # Ubuntu 20.04 PC (por defecto)
                    'pc-i440fx-focal-hpb', # Con host-phys-bits=true
                    'pc-i440fx-eoan',    # Ubuntu 19.10 (fallback)
                    'pc-i440fx-xenial',  # Ubuntu 16.04 (fallback)
                    'pc'                 # Genérico (último recurso)
                ]
                
                # Buscar el primer tipo disponible
                for machine_type in preferred_types:
                    if machine_type in machine_types:
                        logger.info(f"Using machine type '{machine_type}' for {server_name}")
                        return machine_type
                
                logger.warning(f"No preferred machine type found for {server_name}, using 'ubuntu'")
                return 'ubuntu'
                
            else:
                logger.error(f"Failed to get machine types for {server_name}: {result.stderr}")
                return 'ubuntu'  # Fallback seguro
                
        except Exception as e:
            logger.error(f"Error detecting machine type for {server_name}: {e}")
            return 'ubuntu'  # Fallback seguro
    
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
    
    def _get_compatible_machine_type(self, server_name: str) -> str:
        """Obtiene un tipo de máquina compatible para el servidor"""
        try:
            server_ip = self.hypervisors[server_name]['ip']
            
            # Obtener tipos de máquina disponibles
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', 'qemu-system-x86_64', '-machine', 'help']
            result = subprocess.run(ssh_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                machine_types = result.stdout
                
                # Prioridad para servidores Ubuntu 20.04 con QEMU 4.2.1
                preferred_types = [
                    'ubuntu',            # Alias para pc-i440fx-focal
                    'pc-i440fx-focal',   # Ubuntu 20.04 PC (por defecto)
                    'pc-i440fx-focal-hpb', # Con host-phys-bits=true
                    'pc-i440fx-eoan',    # Ubuntu 19.10 (fallback)
                    'pc-i440fx-xenial',  # Ubuntu 16.04 (fallback)
                    'pc'                 # Genérico (último recurso)
                ]
                
                # Buscar el primer tipo disponible
                for machine_type in preferred_types:
                    if machine_type in machine_types:
                        logger.info(f"Using machine type '{machine_type}' for {server_name}")
                        return machine_type
                
                logger.warning(f"No preferred machine type found for {server_name}, using 'ubuntu'")
                return 'ubuntu'
                
            else:
                logger.error(f"Failed to get machine types for {server_name}: {result.stderr}")
                return 'ubuntu'  # Fallback seguro
                
        except Exception as e:
            logger.error(f"Error detecting machine type for {server_name}: {e}")
            return 'ubuntu'  # Fallback seguro

    def _prepare_vm_disk(self, vm_config: Dict, server_name: str) -> str:
        """Prepara disco de la VM"""
        vm_name = vm_config['name']
        base_image = self.available_images[vm_config['image']]['path']
        
        # Usar directorio del usuario ubuntu con permisos completos
        vm_disk_path = f"/home/ubuntu/vm-disks/{vm_name}.qcow2"
        
        # Crear directorio si no existe
        server_ip = self.hypervisors[server_name]['ip']
        
        # Crear directorio con permisos correctos
        setup_cmds = [
            f'mkdir -p /home/ubuntu/vm-disks',
            f'chmod 755 /home/ubuntu/vm-disks'
        ]
        
        for cmd in setup_cmds:
            ssh_cmd = ['ssh', f'ubuntu@{server_ip}', cmd]
            try:
                subprocess.run(ssh_cmd, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError:
                pass  # Directory might already exist
        
        # Crear disco usando qemu-img con backing file
        cmd = [
            'qemu-img', 'create', '-f', 'qcow2',
            '-F', 'qcow2', '-b', base_image,
            vm_disk_path, f"{vm_config['disk']}G"
        ]
        
        ssh_cmd = ['ssh', f'ubuntu@{server_ip}'] + cmd
        
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
        """Genera XML de configuración de la VM con múltiples redes R5"""
        
        vm_name = vm_config['name']
        vm_uuid = str(uuid.uuid4())
        ram_mb = vm_config['ram']
        vcpus = vm_config['cpu']
        
        # Usar tipo de máquina compatible
        machine_type = self._get_compatible_machine_type(server_name)
        
        # Generar interfaces de red para cada red del slice
        network_interfaces = ""
        interface_count = 0
        
        if networks:
            for network in networks:
                network_type = network.get('type', 'data')
                bridge = network.get('bridge', 'ovs1')
                vlan_id = network.get('vlan_id')
                
                # Generar MAC address única para cada interfaz
                mac_address = self._generate_mac_address(vm_name, server_name, interface_count)
                
                # Slot PCI para la interfaz
                pci_slot = f"0x{3 + interface_count:02x}"
                
                if network_type == 'management':
                    # Interfaz de management (bridge directo)
                    network_interfaces += f'''
        <interface type='bridge'>
        <mac address='{mac_address}'/>
        <source bridge='{bridge}'/>
        <model type='virtio'/>
        <address type='pci' domain='0x0000' bus='0x00' slot='{pci_slot}' function='0x0'/>
        </interface>'''
                else:
                    # Interfaz con VLAN (OVS)
                    vlan_config = f'<vlan><tag id="{vlan_id}"/></vlan>' if vlan_id else ''
                    network_interfaces += f'''
        <interface type='bridge'>
        <mac address='{mac_address}'/>
        <source bridge='{bridge}'/>
        <virtualport type='openvswitch'/>
        {vlan_config}
        <model type='virtio'/>
        <address type='pci' domain='0x0000' bus='0x00' slot='{pci_slot}' function='0x0'/>
        </interface>'''
                
                interface_count += 1
        else:
            # Fallback: interfaz por defecto
            mac_address = self._generate_mac_address(vm_name, server_name, 0)
            network_interfaces = f'''
        <interface type='bridge'>
        <mac address='{mac_address}'/>
        <source bridge='{self.ovs_bridge}'/>
        <virtualport type='openvswitch'/>
        <model type='virtio'/>
        <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
        </interface>'''

        xml_template = f"""<domain type='kvm'>
    <name>{vm_name}</name>
    <uuid>{vm_uuid}</uuid>
    <metadata>
        <pucp:slice_id xmlns:pucp='http://pucp.edu.pe/orchestrator'>{slice_id or 'unknown'}</pucp:slice_id>
        <pucp:server xmlns:pucp='http://pucp.edu.pe/orchestrator'>{server_name}</pucp:server>
        <pucp:internet_access xmlns:pucp='http://pucp.edu.pe/orchestrator'>{vm_config.get('internet_access', False)}</pucp:internet_access>
    </metadata>
    <memory unit='MiB'>{ram_mb}</memory>
    <currentMemory unit='MiB'>{ram_mb}</currentMemory>
    <vcpu placement='static'>{vcpus}</vcpu>
    <os>
        <type arch='x86_64' machine='{machine_type}'>hvm</type>
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
        <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
        </disk>
        
        <!-- Controladores PCI -->
        <controller type='pci' index='0' model='pci-root'/>
        <controller type='usb' index='0' model='piix3-uhci'>
        <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
        </controller>
        
        <!-- Interfaces de red múltiples R5 -->
        {network_interfaces}
        
        <!-- Resto de dispositivos... -->
        <serial type='pty'>
        <target type='isa-serial' port='0'>
            <model name='isa-serial'/>
        </target>
        </serial>
        <console type='pty'>
        <target type='serial' port='0'/>
        </console>
        
        <input type='tablet' bus='usb'>
        <address type='usb' bus='0' port='1'/>
        </input>
        <input type='mouse' bus='ps2'/>
        <input type='keyboard' bus='ps2'/>
        
        <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
        <listen type='address' address='0.0.0.0'/>
        </graphics>
        
        <video>
        <model type='cirrus' vram='16384' heads='1' primary='yes'/>
        <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
        </video>
        
        <memballoon model='virtio'>
        <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
        </memballoon>
    </devices>
    </domain>"""
        
        return xml_template

    def _generate_mac_address(self, vm_name: str, server_name: str, interface_id: int = 0) -> str:
        """Genera MAC address única para cada interfaz"""
        import hashlib
        hash_input = f"{vm_name}-{server_name}-{interface_id}".encode()
        hash_value = hashlib.md5(hash_input).hexdigest()
        
        # Formato MAC: 52:54:XX:XX:XX:XX (prefijo KVM)
        mac = f"52:54:{hash_value[0:2]}:{hash_value[2:4]}:{hash_value[4:6]}:{hash_value[6:8]}"
        return mac


    def _get_auth_token(self) -> Optional[str]:
        """Obtiene token de autenticación para Network Service"""
        try:
            import requests
            auth_response = requests.post(
                'http://localhost:5001/login',
                json={'username': 'testuser', 'password': 'testpass123'},
                timeout=10
            )
            if auth_response.status_code == 200:
                token = auth_response.json().get('token')
                logger.info("✓ Token obtenido para Network Service")
                return token
            else:
                logger.warning("No se pudo obtener token para Network Service")
                return None
        except Exception as e:
            logger.warning(f"Error obteniendo token: {e}")
            return None

    def _execute_ssh_command(self, server_name: str, command: str, timeout: int = 60) -> Dict:
        """Ejecuta comando SSH sin conflictos de puerto"""
        if server_name not in self.hypervisors:
            return {
                'success': False,
                'error': f'Unknown server: {server_name}',
                'output': ''
            }
        
        server_config = self.hypervisors[server_name]
        server_ip = server_config['ip']
        
        try:
            # SSH directo sin port forwarding problemático
            ssh_command = [
                'ssh',
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=30',
                '-o', 'ServerAliveInterval=10',
                '-o', 'ServerAliveCountMax=3',
                '-o', 'LogLevel=ERROR',  # Reducir ruido en logs
                f'ubuntu@{server_ip}',
                command
            ]
            
            logger.debug(f"Executing on {server_name}: {command}")
            
            # Ejecutar con timeout
            result = subprocess.run(
                ssh_command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip(),
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Command timeout after {timeout}s',
                'output': ''
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output': ''
            }
    
    def _create_disk(self, vm_name: str, base_image: str, server_name: str) -> str:
        """Crea disco de VM con manejo robusto de errores"""
        try:
            # Directorio de discos
            disk_dir = '/home/ubuntu/vm-disks'
            disk_path = f"{disk_dir}/{vm_name}.qcow2"
            
            # 1. Configurar directorio con permisos correctos
            setup_commands = [
                f"sudo mkdir -p {disk_dir}",
                f"sudo chown ubuntu:ubuntu {disk_dir}",
                f"sudo chmod 755 {disk_dir}"
            ]
            
            for cmd in setup_commands:
                result = self._execute_ssh_command(server_name, cmd)
                if not result['success']:
                    logger.warning(f"Setup command failed: {cmd} - {result['error']}")
            
            # 2. Verificar imagen base
            if base_image in self.available_images:
                base_path = self.available_images[base_image]['path']
                
                # Verificar acceso a imagen base
                check_result = self._execute_ssh_command(server_name, f"ls -la {base_path}")
                if not check_result['success']:
                    raise Exception(f"Base image not accessible: {base_path}")
                
                # Crear disco basado en imagen
                create_cmd = f"qemu-img create -f qcow2 -F qcow2 -b {base_path} {disk_path}"
            else:
                logger.warning(f"Unknown base image {base_image}, creating empty disk")
                create_cmd = f"qemu-img create -f qcow2 {disk_path} 10G"
            
            # 3. Crear disco
            logger.info(f"Creating disk on {server_name}: {create_cmd}")
            result = self._execute_ssh_command(server_name, create_cmd)
            
            if result['success']:
                # Verificar que se creó
                verify_result = self._execute_ssh_command(server_name, f"ls -la {disk_path}")
                if verify_result['success']:
                    logger.info(f"✓ Disk created successfully: {disk_path}")
                    return disk_path
                else:
                    raise Exception(f"Disk file not found after creation: {disk_path}")
            else:
                raise Exception(f"Disk creation failed: {result['error']}")
                
        except Exception as e:
            logger.error(f"Failed to create disk for {vm_name}: {e}")
            raise
    
    def _execute_commands_on_servers(self, commands: List[str], description: str = "commands"):
        """Ejecuta comandos en todos los servidores del cluster"""
        results = []
        errors = []
        
        for server_name in self.hypervisors.keys():
            server_results = []
            for command in commands:
                try:
                    result = self._execute_ssh_command(server_name, command)
                    server_results.append({
                        'server': server_name,
                        'command': command,
                        'success': result['success'],
                        'output': result.get('output', ''),
                        'error': result.get('error', '')
                    })
                    
                    if result['success']:
                        logger.info(f"✓ {server_name}: {command}")
                    else:
                        logger.warning(f"✗ {server_name}: {command} - {result.get('error', 'Unknown error')}")
                        errors.append(f"{server_name}: {command} failed")
                        
                except Exception as e:
                    error_msg = f"{server_name}: {command} - {str(e)}"
                    logger.error(f"✗ {error_msg}")
                    errors.append(error_msg)
                    server_results.append({
                        'server': server_name,
                        'command': command,
                        'success': False,
                        'output': '',
                        'error': str(e)
                    })
            
            results.extend(server_results)
        
        if not errors:
            logger.info(f"Commands executed successfully for {description}")
        else:
            logger.warning(f"Some commands failed for {description}: {len(errors)} errors")
        
        return {
            'success': len(errors) == 0,
            'results': results,
            'errors': errors
        }

class NetworkServiceClient:
    """Cliente para interactuar con Network Service"""
    
    def __init__(self, base_url="http://localhost:5004", token=None):
        self.base_url = base_url
        self.timeout = 120
        self.token = token
        self.headers = {'Content-Type': 'application/json'}
        
        # Agregar autorización si tenemos token
        if self.token:
            self.headers['Authorization'] = f'Bearer {self.token}'
    
    def set_token(self, token: str):
        """Establecer token de autenticación"""
        self.token = token
        self.headers['Authorization'] = f'Bearer {token}'
    
    def allocate_vlan(self, infrastructure: str, network_id: str, slice_id: str, 
                     description: str = None, network_type: str = 'data') -> Optional[int]:
        """Solicita asignación de VLAN al Network Service"""
        try:
            payload = {
                'infrastructure': infrastructure,
                'network_id': network_id,
                'slice_id': slice_id,
                'description': description or f'VLAN for {network_type} network',
                'network_type': network_type
            }
            
            response = requests.post(
                f"{self.base_url}/api/vlans/allocate",
                json=payload,
                headers=self.headers,  # ← Usar headers con auth
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                vlan_id = result.get('vlan_id')
                logger.info(f"✓ VLAN {vlan_id} allocated for {network_type} network")
                return vlan_id
            else:
                logger.error(f"VLAN allocation failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error communicating with Network Service: {e}")
            return None
    
    def create_provider_network(self, network_config: Dict) -> Dict:
        """Crea red provider usando Network Service"""
        try:
            response = requests.post(
                f"{self.base_url}/api/networks",
                json=network_config,
                headers=self.headers,  # ← Usar headers con auth
                timeout=self.timeout
            )
            
            if response.status_code == 201:
                result = response.json()
                logger.info(f"✓ Provider network created: {result['name']}")
                return result
            else:
                logger.error(f"Provider network creation failed: {response.status_code}")
                raise Exception(f"Network Service error: {response.text}")
                
        except Exception as e:
            logger.error(f"Error creating provider network: {e}")
            raise
    
    def configure_security_rules(self, network_id: str, rules: List[Dict]) -> bool:
        """Configura reglas de seguridad en Network Service"""
        try:
            for rule in rules:
                response = requests.post(
                    f"{self.base_url}/api/networks/{network_id}/security-rules",
                    json=rule,
                    headers=self.headers,  # ← Usar headers con auth
                    timeout=self.timeout
                )
                
                if response.status_code != 201:
                    logger.warning(f"Security rule creation failed: {response.text}")
                    return False
            
            logger.info(f"✓ Security rules configured for network {network_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error configuring security rules: {e}")
            return False
    
    def release_slice_vlans(self, slice_id: str) -> bool:
        """Libera todas las VLANs de un slice"""
        try:
            response = requests.post(
                f"{self.base_url}/api/vlans/slice/{slice_id}/release",
                headers=self.headers,  # ← Usar headers con auth
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✓ Released {result.get('released_count', 0)} VLANs for slice {slice_id}")
                return True
            else:
                logger.warning(f"VLAN release failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error releasing VLANs: {e}")
            return False