# template_service/advanced_topology_generator.py
import json
import uuid
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class TopologyType:
    LINEAR = "linear"
    RING = "ring" 
    STAR = "star"
    MESH = "mesh"
    TREE = "tree"
    BUS = "bus"
    CUSTOM = "custom"

class FlavorManager:
    """Gestión de flavors compatible con tu sistema anterior"""
    
    DEFAULT_FLAVORS = {
        "tiny": {"cpu": 1, "ram": 512, "disk": 1},
        "small": {"cpu": 1, "ram": 1024, "disk": 10}, 
        "medium": {"cpu": 2, "ram": 2048, "disk": 20},
        "large": {"cpu": 4, "ram": 4096, "disk": 40}
    }
    
    @classmethod
    def get_flavor(cls, flavor_name: str) -> Dict:
        """Obtiene configuración de flavor"""
        return cls.DEFAULT_FLAVORS.get(flavor_name, cls.DEFAULT_FLAVORS["small"])
    
    @classmethod
    def list_flavors(cls) -> List[str]:
        """Lista flavors disponibles"""
        return list(cls.DEFAULT_FLAVORS.keys())

class AdvancedTopologyGenerator:
    """
    Generador avanzado que integra tu TopologyManager con el sistema actual
    """
    
    def __init__(self):
        self.default_nodes = {
            "head_node": "10.0.10.1",
            "ofs_node": "10.0.10.5", 
            "workers": ["10.0.10.2", "10.0.10.3", "10.0.10.4"]
        }
        
        self.default_interfaces = {
            "head_internet": "ens3",
            "head_ofs": "ens4", 
            "worker_ofs": "ens4"
        }
    
    def generate_mac_address(self, worker_id: int, vm_num: int) -> str:
        """Genera dirección MAC única basada en worker y VM"""
        mac_prefix = "52:54:00"
        return f"{mac_prefix}:{worker_id:02x}:{vm_num:02x}:{(vm_num + worker_id):02x}"
    
    def distribute_vms_to_workers(self, num_vms: int) -> List[Tuple[int, int]]:
        """
        Distribuye VMs entre workers usando round-robin
        Returns: Lista de (worker_id, vnc_port) para cada VM
        """
        distribution = []
        for i in range(num_vms):
            worker_id = (i % 3) + 1  # Workers 1, 2, 3
            vnc_port = (i % 5) + 1   # VNC ports 1-5 per worker
            distribution.append((worker_id, vnc_port))
        return distribution
    
    def create_ring_topology(self, num_vms: int, flavor: str = "small", 
                           start_vm_id: int = 1, enable_internet: bool = False,
                           internet_vms: List[str] = None) -> Dict:
        """Crea topología en anillo compatible con slice_service"""
        
        if num_vms < 3:
            raise ValueError("Ring topology requires at least 3 VMs")
        
        topology = {
            "name": f"ring_topology_{num_vms}vms",
            "infrastructure": "linux",  # Default, puede ser cambiado
            "topology_type": TopologyType.RING,
            "vms": [],
            "networks": [],
            "connections": [],
            "settings": {
                "enable_internet": enable_internet,
                "enable_vlan_communication": True
            },
            "vm_internet_access": internet_vms or []
        }
        
        # Distribuir VMs entre workers
        distribution = self.distribute_vms_to_workers(num_vms)
        flavor_config = FlavorManager.get_flavor(flavor)
        
        # Crear VMs
        for i in range(num_vms):
            vm_id = start_vm_id + i
            vm_name = f"vm{vm_id}"
            worker_id, vnc_port = distribution[i]
            
            vm = {
                "name": vm_name,
                "image": "ubuntu-20.04",  # Default image
                "flavor": flavor_config,
                "worker": worker_id,
                "vnc_port": vnc_port,
                "mac": self.generate_mac_address(worker_id, vm_id)
            }
            topology["vms"].append(vm)
        
        # Crear conexiones en anillo
        for i in range(num_vms):
            current_vm = topology["vms"][i]["name"]
            next_vm = topology["vms"][(i + 1) % num_vms]["name"]
            
            # Conexión bidireccional
            topology["connections"].extend([
                {"from": current_vm, "to": next_vm},
                {"from": next_vm, "to": current_vm}
            ])
        
        # Crear red para el anillo
        topology["networks"].append({
            "name": "ring_network",
            "cidr": "192.168.100.0/24",
            "gateway": "192.168.100.1"
        })
        
        return topology
    
    def create_star_topology(self, num_vms: int, flavor: str = "small",
                           start_vm_id: int = 1, enable_internet: bool = False,
                           internet_vms: List[str] = None) -> Dict:
        """Crea topología en estrella"""
        
        if num_vms < 2:
            raise ValueError("Star topology requires at least 2 VMs")
        
        topology = {
            "name": f"star_topology_{num_vms}vms",
            "infrastructure": "linux",
            "topology_type": TopologyType.STAR,
            "vms": [],
            "networks": [],
            "connections": [],
            "settings": {
                "enable_internet": enable_internet,
                "enable_vlan_communication": True
            },
            "vm_internet_access": internet_vms or []
        }
        
        distribution = self.distribute_vms_to_workers(num_vms)
        flavor_config = FlavorManager.get_flavor(flavor)
        
        # Crear VMs
        for i in range(num_vms):
            vm_id = start_vm_id + i
            vm_name = f"vm{vm_id}"
            worker_id, vnc_port = distribution[i]
            
            vm = {
                "name": vm_name,
                "image": "ubuntu-20.04",
                "flavor": flavor_config,
                "worker": worker_id,
                "vnc_port": vnc_port,
                "mac": self.generate_mac_address(worker_id, vm_id)
            }
            topology["vms"].append(vm)
        
        # VM centro (primera VM)
        center_vm = topology["vms"][0]["name"]
        
        # Crear conexiones estrella
        for i in range(1, num_vms):
            edge_vm = topology["vms"][i]["name"]
            
            # Conexión bidireccional centro-extremo
            topology["connections"].extend([
                {"from": center_vm, "to": edge_vm},
                {"from": edge_vm, "to": center_vm}
            ])
        
        # Crear red para la estrella
        topology["networks"].append({
            "name": "star_network",
            "cidr": "192.168.101.0/24",
            "gateway": "192.168.101.1"
        })
        
        return topology
    
    def create_linear_topology(self, num_vms: int, flavor: str = "small",
                             start_vm_id: int = 1, enable_internet: bool = False,
                             internet_vms: List[str] = None) -> Dict:
        """Crea topología lineal"""
        
        if num_vms < 2:
            raise ValueError("Linear topology requires at least 2 VMs")
        
        topology = {
            "name": f"linear_topology_{num_vms}vms",
            "infrastructure": "linux",
            "topology_type": TopologyType.LINEAR,
            "vms": [],
            "networks": [],
            "connections": [],
            "settings": {
                "enable_internet": enable_internet,
                "enable_vlan_communication": True
            },
            "vm_internet_access": internet_vms or []
        }
        
        distribution = self.distribute_vms_to_workers(num_vms)
        flavor_config = FlavorManager.get_flavor(flavor)
        
        # Crear VMs
        for i in range(num_vms):
            vm_id = start_vm_id + i
            vm_name = f"vm{vm_id}"
            worker_id, vnc_port = distribution[i]
            
            vm = {
                "name": vm_name,
                "image": "ubuntu-20.04",
                "flavor": flavor_config,
                "worker": worker_id,
                "vnc_port": vnc_port,
                "mac": self.generate_mac_address(worker_id, vm_id)
            }
            topology["vms"].append(vm)
        
        # Crear conexiones lineales
        for i in range(num_vms - 1):
            current_vm = topology["vms"][i]["name"]
            next_vm = topology["vms"][i + 1]["name"]
            
            # Conexión bidireccional
            topology["connections"].extend([
                {"from": current_vm, "to": next_vm},
                {"from": next_vm, "to": current_vm}
            ])
        
        # Crear red para la línea
        topology["networks"].append({
            "name": "linear_network",
            "cidr": "192.168.102.0/24",
            "gateway": "192.168.102.1"
        })
        
        return topology
    
    def create_mesh_topology(self, num_vms: int, flavor: str = "small",
                           start_vm_id: int = 1, enable_internet: bool = False,
                           internet_vms: List[str] = None) -> Dict:
        """Crea topología en malla completa"""
        
        topology = {
            "name": f"mesh_topology_{num_vms}vms",
            "infrastructure": "linux",
            "topology_type": TopologyType.MESH,
            "vms": [],
            "networks": [],
            "connections": [],
            "settings": {
                "enable_internet": enable_internet,
                "enable_vlan_communication": True
            },
            "vm_internet_access": internet_vms or []
        }
        
        distribution = self.distribute_vms_to_workers(num_vms)
        flavor_config = FlavorManager.get_flavor(flavor)
        
        # Crear VMs
        for i in range(num_vms):
            vm_id = start_vm_id + i
            vm_name = f"vm{vm_id}"
            worker_id, vnc_port = distribution[i]
            
            vm = {
                "name": vm_name,
                "image": "ubuntu-20.04",
                "flavor": flavor_config,
                "worker": worker_id,
                "vnc_port": vnc_port,
                "mac": self.generate_mac_address(worker_id, vm_id)
            }
            topology["vms"].append(vm)
        
        # Crear conexiones de malla completa (todos con todos)
        for i in range(num_vms):
            for j in range(i + 1, num_vms):
                vm1 = topology["vms"][i]["name"]
                vm2 = topology["vms"][j]["name"]
                
                # Conexión bidireccional
                topology["connections"].extend([
                    {"from": vm1, "to": vm2},
                    {"from": vm2, "to": vm1}
                ])
        
        # Crear red para la malla
        topology["networks"].append({
            "name": "mesh_network",
            "cidr": "192.168.103.0/24",
            "gateway": "192.168.103.1"
        })
        
        return topology
    
    def create_custom_topology(self, vms_config: List[Dict], 
                             connections_config: List[Dict],
                             networks_config: List[Dict] = None,
                             enable_internet: bool = False,
                             internet_vms: List[str] = None) -> Dict:
        """
        Crea topología personalizada
        
        Args:
            vms_config: Lista de configuraciones de VMs
            connections_config: Lista de conexiones
            networks_config: Configuración de redes (opcional)
            enable_internet: Habilitar acceso a internet
            internet_vms: VMs con acceso a internet
        """
        
        topology = {
            "name": f"custom_topology_{len(vms_config)}vms",
            "infrastructure": "linux",
            "topology_type": TopologyType.CUSTOM,
            "vms": [],
            "networks": networks_config or [],
            "connections": connections_config,
            "settings": {
                "enable_internet": enable_internet,
                "enable_vlan_communication": True
            },
            "vm_internet_access": internet_vms or []
        }
        
        # Procesar configuración de VMs
        for i, vm_config in enumerate(vms_config):
            vm_name = vm_config.get("name", f"vm{i+1}")
            flavor = vm_config.get("flavor", "small")
            worker_id = vm_config.get("worker", (i % 3) + 1)
            vnc_port = vm_config.get("vnc_port", (i % 5) + 1)
            
            vm = {
                "name": vm_name,
                "image": vm_config.get("image", "ubuntu-20.04"),
                "flavor": FlavorManager.get_flavor(flavor),
                "worker": worker_id,
                "vnc_port": vnc_port,
                "mac": vm_config.get("mac", self.generate_mac_address(worker_id, i+1))
            }
            topology["vms"].append(vm)
        
        # Si no se proporcionaron redes, crear una por defecto
        if not topology["networks"]:
            topology["networks"].append({
                "name": "custom_network",
                "cidr": "192.168.104.0/24",
                "gateway": "192.168.104.1"
            })
        
        return topology
    
    def convert_to_slice_format(self, topology: Dict) -> Dict:
        """
        Convierte topología a formato compatible con slice_service
        """
        slice_data = {
            "name": topology["name"],
            "description": f"Generated {topology['topology_type']} topology",
            "infrastructure": topology["infrastructure"],
            "vms": [],
            "networks": topology["networks"],
            "connections": topology["connections"]
        }
        
        # Convertir VMs al formato de slice_service
        for vm in topology["vms"]:
            slice_vm = {
                "name": vm["name"],
                "cpu": vm["flavor"]["cpu"],
                "ram": vm["flavor"]["ram"],
                "disk": vm["flavor"]["disk"],
                "image_id": vm["image"]
            }
            slice_data["vms"].append(slice_vm)
        
        # Agregar configuración de internet si está habilitada
        if topology["settings"]["enable_internet"]:
            slice_data["vm_internet_access"] = topology["vm_internet_access"]
        
        return slice_data
    
    def save_topology_json(self, topology: Dict, filename: str = None) -> str:
        """
        Guarda topología en formato JSON compatible con tu sistema anterior
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{topology['name']}_{timestamp}.json"
        
        # Formato completo compatible con create_flexible_topology.sh
        full_topology = {
            "name": topology["name"],
            "nodes": self.default_nodes,
            "interfaces": self.default_interfaces,
            "vms": topology["vms"],
            "connections": topology["connections"],
            "networks": topology["networks"],
            "settings": topology["settings"],
            "vm_internet_access": topology["vm_internet_access"]
        }
        
        with open(filename, 'w') as f:
            json.dump(full_topology, f, indent=2)
        
        logger.info(f"Topology saved to {filename}")
        return filename