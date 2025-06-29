import logging
import time
import uuid
from typing import Dict, List, Any, Optional
import ipaddress

from .base_driver import BaseDriver
from slice_service.openstack.config import OpenStackConfig
from slice_service.openstack.api_client import OpenStackAPIClient

logger = logging.getLogger(__name__)

class OpenStackDriver(BaseDriver):
    
    def __init__(self):
        super().__init__()
        
        self.config = OpenStackConfig()
        
        self.api_client = OpenStackAPIClient(self.config.get_auth_config())
        
        self._flavors_cache = {}
        self._images_cache = {}
        self._networks_cache = {}
        
        self._verify_connection()
        
        logger.info("Controlador de OpenStack inicializado exitosamente")
    
    def _verify_connection(self):
        try:
            self.api_client.session.get_token()
            self.api_client.nova.servers.list()
            self.api_client.neutron.list_networks()
            logger.info("Conexión a OpenStack verificada")
        except Exception as e:
            logger.error(f"Error al conectar con OpenStack: {e}")
            raise
    
    def get_infrastructure_type(self) -> str:
        return "openstack"
    
    def get_available_resources(self) -> Dict[str, Any]:
        try:
            hypervisor_stats = self.api_client.nova.hypervisor_stats.statistics()
            quotas = self.api_client.nova.quotas.get(self.config.auth['project_name'])
            servers = self.api_client.list_servers()
            
            resources = {
                'infrastructure': 'openstack',
                'hypervisors': {
                    'count': hypervisor_stats.count,
                    'vcpus_total': hypervisor_stats.vcpus,
                    'vcpus_used': hypervisor_stats.vcpus_used,
                    'memory_total_mb': hypervisor_stats.memory_mb,
                    'memory_used_mb': hypervisor_stats.memory_mb_used,
                    'disk_total_gb': hypervisor_stats.local_gb,
                    'disk_used_gb': hypervisor_stats.local_gb_used,
                    'running_vms': hypervisor_stats.running_vms
                },
                'quotas': {
                    'instances': quotas.instances,
                    'cores': quotas.cores,
                    'ram': quotas.ram,
                    'floating_ips': quotas.floating_ips,
                    'security_groups': quotas.security_groups
                },
                'availability_zones': self.config.get_availability_zones(),
                'current_instances': len(servers)
            }
            
            hypervisors = self.api_client.nova.hypervisors.list()
            resources['hypervisor_details'] = {}
            
            for hypervisor in hypervisors:
                resources['hypervisor_details'][hypervisor.hypervisor_hostname] = {
                    'vcpus': hypervisor.vcpus,
                    'vcpus_used': hypervisor.vcpus_used,
                    'memory_mb': hypervisor.memory_mb,
                    'memory_mb_used': hypervisor.memory_mb_used,
                    'local_gb': hypervisor.local_gb,
                    'local_gb_used': hypervisor.local_gb_used,
                    'running_vms': hypervisor.running_vms,
                    'state': hypervisor.state,
                    'status': hypervisor.status
                }
            
            return resources
            
        except Exception as e:
            logger.error(f"Error al obtener los recursos de OpenStack: {e}")
            raise
    
    def _ensure_flavor_exists(self, flavor_name: str) -> str:
        if flavor_name in self._flavors_cache:
            return self._flavors_cache[flavor_name]
        
        flavor = self.api_client.find_flavor(flavor_name)
        if flavor:
            self._flavors_cache[flavor_name] = flavor.id
            return flavor.id
        
        if flavor_name in self.config.flavors:
            flavor_config = self.config.flavors[flavor_name]
            flavor = self.api_client.create_flavor(
                name=flavor_name,
                ram=flavor_config['ram'],
                vcpus=flavor_config['vcpus'],
                disk=flavor_config['disk']
            )
            self._flavors_cache[flavor_name] = flavor.id
            logger.info(f"Se creó el sabor {flavor_name}")
            return flavor.id
        else:
            raise ValueError(f"Sabor desconocido: {flavor_name}")
    
    def _ensure_image_exists(self, image_name: str) -> str:
        if image_name in self._images_cache:
            return self._images_cache[image_name]
        
        image = self.api_client.find_image(image_name)
        if image:
            self._images_cache[image_name] = image.id
            return image.id
        
        image_mappings = {
            'ubuntu-20.04': 'ubuntu-20.04-server',
            'ubuntu': 'ubuntu-20.04-server',
            'cirros': 'cirros-0.5.2'
        }
        
        mapped_name = image_mappings.get(image_name, image_name)
        image = self.api_client.find_image(mapped_name)
        if image:
            self._images_cache[image_name] = image.id
            return image.id
        
        raise ValueError(f"Imagen no encontrada: {image_name}")
    
    def create_vm(self, vm_config: Dict[str, Any], placement: Dict[str, Any] = None) -> Dict[str, Any]:
        try:
            vm_name = vm_config['name']
            logger.info(f"Creando la VM {vm_name} en OpenStack")
            
            flavor_id = self._ensure_flavor_exists(vm_config.get('flavor', 'small'))
            image_id = self._ensure_image_exists(vm_config.get('image', 'ubuntu-20.04'))
            
            network_id = None
            if 'network' in vm_config:
                network = self._ensure_network_exists(vm_config['network'])
                network_id = network['id']
            
            availability_zone = None
            if placement and 'zone' in placement:
                availability_zone = placement['zone']
            elif placement and 'hostname' in placement:
                for node in self.config.compute_nodes.values():
                    if node['hostname'] == placement['hostname']:
                        availability_zone = node.get('availability_zone', 'nova')
                        break
            
            security_groups = vm_config.get('security_groups', ['default'])
            user_data = vm_config.get('user_data', '')
            if not user_data:
                user_data = f"""#cloud-config
hostname: {vm_name}
manage_etc_hosts: true
"""
            
            server = self.api_client.create_server(
                name=vm_name,
                image_id=image_id,
                flavor_id=flavor_id,
                network_id=network_id,
                security_groups=security_groups,
                availability_zone=availability_zone,
                user_data=user_data
            )
            
            logger.info(f"Esperando a que la VM {vm_name} se active...")
            if self.api_client.wait_for_server_active(server.id, timeout=300):
                server = self.api_client.get_server(server.id)
                
                ip_address = None
                for network_name, addresses in server.addresses.items():
                    if addresses:
                        ip_address = addresses[0]['addr']
                        break
                
                result = {
                    'id': server.id,
                    'name': server.name,
                    'status': server.status,
                    'ip_address': ip_address,
                    'flavor': vm_config.get('flavor', 'small'),
                    'image': vm_config.get('image', 'ubuntu-20.04'),
                    'availability_zone': getattr(server, 'OS-EXT-AZ:availability_zone', 'unknown'),
                    'created_at': server.created,
                    'infrastructure': 'openstack'
                }
                
                logger.info(f"VM {vm_name} creada exitosamente: {result}")
                return result
            else:
                raise Exception(f"Tiempo de espera agotado para que la VM {vm_name} se active")
            
        except Exception as e:
            logger.error(f"Error al crear la VM {vm_config['name']}: {e}")
            raise
    
    def delete_vm(self, vm_id: str) -> bool:
        try:
            logger.info(f"Eliminando la VM {vm_id} de OpenStack")
            self.api_client.delete_server(vm_id)
            
            start_time = time.time()
            while time.time() - start_time < 60:
                try:
                    self.api_client.get_server(vm_id)
                    time.sleep(2)
                except Exception:
                    logger.info(f"VM {vm_id} eliminada exitosamente")
                    return True
            
            logger.warning(f"Tiempo de espera agotado para eliminar la VM {vm_id}")
            return False
            
        except Exception as e:
            logger.error(f"Error al eliminar la VM {vm_id}: {e}")
            raise
    
    def get_vm_info(self, vm_id: str) -> Dict[str, Any]:
        try:
            server = self.api_client.get_server(vm_id)
            
            ip_address = None
            for network_name, addresses in server.addresses.items():
                if addresses:
                    ip_address = addresses[0]['addr']
                    break
            
            return {
                'id': server.id,
                'name': server.name,
                'status': server.status,
                'ip_address': ip_address,
                'created_at': server.created,
                'updated_at': server.updated,
                'availability_zone': getattr(server, 'OS-EXT-AZ:availability_zone', 'unknown'),
                'host': getattr(server, 'OS-EXT-SRV-ATTR:host', 'unknown'),
                'infrastructure': 'openstack'
            }
            
        except Exception as e:
            logger.error(f"Error al obtener la información de la VM {vm_id}: {e}")
            raise
    
    def _ensure_network_exists(self, network_config: Dict[str, Any]) -> Dict[str, Any]:
        network_name = network_config.get('name', f"slice-net-{uuid.uuid4().hex[:8]}")
        
        networks = self.api_client.list_networks()
        for net in networks:
            if net['name'] == network_name:
                logger.info(f"Usando red existente: {network_name}")
                return net
        
        vlan_start, vlan_end = self.config.get_vlan_range()
        
        used_vlans = set()
        for net in networks:
            if 'provider:segmentation_id' in net:
                used_vlans.add(net['provider:segmentation_id'])
        
        vlan_id = None
        for vid in range(vlan_start, vlan_end + 1):
            if vid not in used_vlans:
                vlan_id = vid
                break
        
        if not vlan_id:
            raise Exception("No hay VLANs disponibles")
        
        network = self.api_client.create_network(
            name=network_name,
            provider_network_type='vlan',
            provider_physical_network=self.config.network_config['physical_network'],
            provider_segmentation_id=vlan_id,
            shared=False
        )
        
        logger.info(f"Red {network_name} creada con VLAN {vlan_id}")
        
        cidr = network_config.get('cidr', f'10.60.{vlan_id}.0/24')
        gateway = network_config.get('gateway')
        if not gateway:
            network_obj = ipaddress.IPv4Network(cidr)
            gateway = str(list(network_obj.hosts())[0])
        
        subnet = self.api_client.create_subnet(
            network_id=network['id'],
            cidr=cidr,
            name=f"{network_name}-subnet",
            gateway_ip=gateway,
            enable_dhcp=True,
            dns_nameservers=['8.8.8.8', '8.8.4.4']
        )
        
        logger.info(f"Subred {subnet['name']} creada con CIDR {cidr}")
        
        return network
    
    def create_network(self, network_config: Dict[str, Any]) -> Dict[str, Any]:
        try:
            network = self._ensure_network_exists(network_config)
            return {
                'id': network['id'],
                'name': network['name'],
                'vlan_id': network.get('provider:segmentation_id'),
                'status': 'active',
                'infrastructure': 'openstack'
            }
        except Exception as e:
            logger.error(f"Error al crear la red: {e}")
            raise
    
    def delete_network(self, network_id: str) -> bool:
        try:
            logger.info(f"Eliminando la red {network_id}")
            ports = self.api_client.neutron.list_ports(network_id=network_id)['ports']
            for port in ports:
                if port['device_owner'] not in ['network:dhcp', 'network:router_interface']:
                    self.api_client.delete_port(port['id'])
            
            subnets = self.api_client.neutron.list_subnets(network_id=network_id)['subnets']
            for subnet in subnets:
                self.api_client.neutron.delete_subnet(subnet['id'])
            
            self.api_client.delete_network(network_id)
            logger.info(f"Red {network_id} eliminada exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error al eliminar la red {network_id}: {e}")
            return False
    
    def create_security_group(self, name: str, rules: List[Dict[str, Any]]) -> str:
        try:
            sg = self.api_client.create_security_group(
                name=name,
                description=f"Grupo de seguridad para {name}"
            )
            
            for rule in rules:
                self.api_client.add_security_group_rule(
                    security_group_id=sg['id'],
                    direction=rule.get('direction', 'ingress'),
                    ethertype=rule.get('ethertype', 'IPv4'),
                    protocol=rule.get('protocol'),
                    port_range_min=rule.get('port_range_min'),
                    port_range_max=rule.get('port_range_max'),
                    remote_ip_prefix=rule.get('remote_ip_prefix')
                )
            
            logger.info(f"Grupo de seguridad {name} creado con {len(rules)} reglas")
            return sg['id']
            
        except Exception as e:
            logger.error(f"Error al crear el grupo de seguridad {name}: {e}")
            raise
    
    def get_console_url(self, vm_id: str) -> str:
        try:
            console = self.api_client.nova.servers.get_vnc_console(
                vm_id, 'novnc'
            )
            return console['console']['url']
        except Exception as e:
            logger.error(f"Error al obtener la URL de consola para {vm_id}: {e}")
            return None
    
    def deploy_slice(self, slice_config: Dict[str, Any], placement: Dict[str, Any]) -> Dict[str, Any]:
        deployed_vms = []
        created_networks = []
        created_security_groups = []
        errors = []
        
        slice_id = slice_config.get('id', str(uuid.uuid4()))
        
        try:
            sg_name = f"slice-{slice_id}"
            sg_rules = [
                {
                    'direction': 'ingress',
                    'ethertype': 'IPv4',
                    'remote_group_id': 'self'
                },
                {
                    'direction': 'ingress',
                    'protocol': 'tcp',
                    'port_range_min': 22,
                    'port_range_max': 22,
                    'remote_ip_prefix': '0.0.0.0/0'
                },
                {
                    'direction': 'ingress',
                    'protocol': 'icmp',
                    'remote_ip_prefix': '0.0.0.0/0'
                }
            ]
            
            if 'security_rules' in slice_config:
                sg_rules.extend(slice_config['security_rules'])
            
            sg_id = self.create_security_group(sg_name, sg_rules)
            created_security_groups.append(sg_id)
            
            for network_config in slice_config.get('networks', []):
                network = self.create_network(network_config)
                created_networks.append(network)
                network_config['id'] = network['id']
            
            for vm_config in slice_config.get('vms', []):
                try:
                    vm_name = vm_config['name']
                    
                    vm_config['security_groups'] = [sg_name]
                    
                    if 'networks' in vm_config and vm_config['networks']:
                        network_name = vm_config['networks'][0]
                        for net in slice_config.get('networks', []):
                            if net['name'] == network_name:
                                vm_config['network'] = net
                                break
                    
                    vm_placement = placement.get(vm_name, {})
                    
                    vm_result = self.create_vm(vm_config, vm_placement)
                    deployed_vms.append(vm_result)
                    
                except Exception as e:
                    error_msg = f"Error al desplegar la VM {vm_config['name']}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            logger.info("Esperando a que todas las VMs estén listas...")
            time.sleep(10)
            
            return {
                'slice_id': slice_id,
                'status': 'error' if errors else 'deployed',
                'deployed_vms': deployed_vms,
                'created_networks': created_networks,
                'security_groups': created_security_groups,
                'errors': errors,
                'infrastructure': 'openstack'
            }
            
        except Exception as e:
            logger.error(f"Error al desplegar el slice: {e}")
            
            for vm in deployed_vms:
                try:
                    self.delete_vm(vm['id'])
                except:
                    pass
            
            for network in created_networks:
                try:
                    self.delete_network(network['id'])
                except:
                    pass
            
            raise
    
    def delete_slice(self, slice_id: str, slice_vms: List[Dict], slice_networks: List[Dict]) -> bool:
        try:
            logger.info(f"Eliminando el slice {slice_id} de OpenStack")
            
            for vm in slice_vms:
                try:
                    self.delete_vm(vm['external_id'])
                except Exception as e:
                    logger.error(f"Error al eliminar la VM {vm['name']}: {e}")
            
            time.sleep(5)
            
            for network in slice_networks:
                try:
                    if 'external_id' in network:
                        self.delete_network(network['external_id'])
                except Exception as e:
                    logger.error(f"Error al eliminar la red {network.get('name', 'desconocida')}: {e}")
            
            try:
                sg_name = f"slice-{slice_id}"
                sgs = self.api_client.neutron.list_security_groups(name=sg_name)['security_groups']
                for sg in sgs:
                    self.api_client.neutron.delete_security_group(sg['id'])
            except Exception as e:
                logger.error(f"Error al eliminar los grupos de seguridad: {e}")
            
            logger.info(f"Slice {slice_id} eliminado exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error al eliminar el slice {slice_id}: {e}")
            return False
    
    def get_supported_images(self) -> List[Dict[str, Any]]:
        try:
            images = self.api_client.list_images()
            supported = []
            
            for image in images:
                if image.status == 'active':
                    supported.append({
                        'id': image.id,
                        'name': image.name,
                        'size': getattr(image, 'size', 0),
                        'min_disk': getattr(image, 'min_disk', 0),
                        'min_ram': getattr(image, 'min_ram', 0),
                        'status': image.status
                    })
            
            return supported
            
        except Exception as e:
            logger.error(f"Error al obtener las imágenes soportadas: {e}")
            return []
    
    def get_supported_flavors(self) -> List[Dict[str, Any]]:
        try:
            flavors = self.api_client.list_flavors()
            supported = []
            
            for flavor in flavors:
                supported.append({
                    'id': flavor.id,
                    'name': flavor.name,
                    'vcpus': flavor.vcpus,
                    'ram': flavor.ram,
                    'disk': flavor.disk
                })
            
            flavor_names = [f['name'] for f in supported]
            for name, config in self.config.flavors.items():
                if name not in flavor_names:
                    supported.append({
                        'id': f'custom-{name}',
                        'name': name,
                        'vcpus': config['vcpus'],
                        'ram': config['ram'],
                        'disk': config['disk']
                    })
            
            return supported
            
        except Exception as e:
            logger.error(f"Error al obtener los flavors soportados: {e}")
            return []