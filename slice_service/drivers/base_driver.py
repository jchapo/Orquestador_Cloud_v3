#!/usr/bin/env python3
"""
Base Driver Interface para PUCP Cloud Orchestrator
Define la interfaz común para todos los drivers de infraestructura
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class BaseDriver(ABC):
    """Interfaz base para todos los drivers de infraestructura"""
    
    def __init__(self):
        self.driver_name = self.__class__.__name__
        self.infrastructure_type = "unknown"
    
    @abstractmethod
    def create_vm(self, vm_config: Dict, server_name: str, 
                  slice_id: str = None, networks: List[Dict] = None) -> Dict:
        """
        Crea una VM en la infraestructura
        
        Args:
            vm_config: Configuración de la VM
            server_name: Servidor donde crear la VM
            slice_id: ID del slice
            networks: Redes a conectar
            
        Returns:
            Dict con información de la VM creada
        """
        pass
    
    @abstractmethod
    def delete_vm(self, vm_name: str, server_name: str, 
                  cleanup_disk: bool = True) -> bool:
        """
        Elimina una VM
        
        Args:
            vm_name: Nombre de la VM
            server_name: Servidor donde está la VM
            cleanup_disk: Si limpiar discos
            
        Returns:
            True si se eliminó correctamente
        """
        pass
    
    @abstractmethod
    def get_vm_status(self, vm_name: str, server_name: str) -> Dict:
        """
        Obtiene estado de una VM
        
        Returns:
            Dict con estado de la VM
        """
        pass
    
    @abstractmethod
    def get_vm_console_url(self, vm_name: str, server_name: str) -> Optional[str]:
        """
        Obtiene URL de consola de la VM
        
        Returns:
            URL de consola o None
        """
        pass
    
    @abstractmethod
    def list_vms(self, server_name: str = None) -> List[Dict]:
        """
        Lista VMs en la infraestructura
        
        Returns:
            Lista de VMs
        """
        pass
    
    @abstractmethod
    def get_server_resources(self, server_name: str = None) -> List[Dict]:
        """
        Obtiene recursos de servidores
        
        Returns:
            Lista con información de recursos
        """
        pass
    
    @abstractmethod
    def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:
        """
        Despliega un slice completo
        
        Args:
            slice_config: Configuración del slice
            placement: Resultado del placement
            
        Returns:
            Resultado del deployment
        """
        pass
    
    @abstractmethod
    def destroy_slice(self, slice_id: str, vm_list: List[Dict]) -> Dict:
        """
        Destruye un slice completo
        
        Args:
            slice_id: ID del slice
            vm_list: Lista de VMs del slice
            
        Returns:
            Resultado de la destrucción
        """
        pass