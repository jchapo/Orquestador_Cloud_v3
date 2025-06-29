#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Orchestrator Module
Maneja la selección y gestión de drivers de infraestructura
"""

import logging
from typing import Optional

# Imports necesarios
try:
    from .drivers.base_driver import BaseDriver
    from .drivers.linux_driver import LinuxClusterDriver
except ImportError:
    # Fallback para imports relativos
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from slice_service.drivers.base_driver import BaseDriver
    from slice_service.drivers.linux_driver import LinuxClusterDriver

logger = logging.getLogger(__name__)

# Verificar disponibilidad de OpenStack driver
try:
    from .drivers.openstack_driver import OpenStackDriver
    OPENSTACK_AVAILABLE = True
except ImportError:
    try:
        from slice_service.drivers.openstack_driver import OpenStackDriver
        OPENSTACK_AVAILABLE = True
    except ImportError:
        OPENSTACK_AVAILABLE = False
        logger.warning("OpenStack driver not available")

class Orchestrator:
    """Orquestador principal para gestión de infraestructuras"""
    
    def __init__(self):
        """Inicializa el orquestador"""
        self._driver_cache = {}
        
    def select_driver(self, infrastructure: str, token: Optional[str] = None) -> BaseDriver:
        """
        Selecciona y retorna el driver apropiado para la infraestructura especificada.
        
        Args:
            infrastructure: Tipo de infraestructura ('linux' o 'openstack')
            token: Token de autenticación para comunicación con otros servicios
            
        Returns:
            BaseDriver: Instancia del driver correspondiente
            
        Raises:
            ValueError: Si el tipo de infraestructura no es soportado
            ImportError: Si el driver no está disponible
        """
        
        # Cache key para evitar recrear drivers innecesariamente
        cache_key = f"{infrastructure}_{token or 'no_token'}"
        
        if cache_key in self._driver_cache:
            logger.debug(f"Using cached driver for {infrastructure}")
            return self._driver_cache[cache_key]
        
        driver = None
        
        try:
            if infrastructure == 'linux':
                driver = LinuxClusterDriver()
                logger.info(f"✓ Linux driver initialized")
                
            elif infrastructure == 'openstack':
                if not OPENSTACK_AVAILABLE:
                    raise ImportError("OpenStack driver not available")
                driver = OpenStackDriver()
                logger.info(f"✓ OpenStack driver initialized")
                
            else:
                supported_types = ['linux', 'openstack']
                raise ValueError(
                    f"Unsupported infrastructure type: '{infrastructure}'. "
                    f"Supported types: {supported_types}"
                )
        
        except ImportError as e:
            logger.error(f"Failed to import driver for {infrastructure}: {e}")
            raise ImportError(
                f"Driver for '{infrastructure}' infrastructure is not available. "
                f"Please ensure the required dependencies are installed. Error: {e}"
            )
        
        except Exception as e:
            logger.error(f"Failed to initialize {infrastructure} driver: {e}")
            raise RuntimeError(
                f"Could not initialize {infrastructure} driver: {e}"
            )
        
        # Cache the driver instance
        self._driver_cache[cache_key] = driver
        
        return driver
    
    def get_available_infrastructures(self) -> list:
        """
        Retorna una lista de infraestructuras disponibles.
        
        Returns:
            list: Lista de tipos de infraestructura disponibles
        """
        available = []
        
        # Test Linux driver
        try:
            LinuxClusterDriver()
            available.append('linux')
            logger.debug("Linux driver available")
        except Exception as e:
            logger.warning(f"Linux driver not available: {e}")
        
        # Test OpenStack driver  
        if OPENSTACK_AVAILABLE:
            try:
                OpenStackDriver()
                available.append('openstack')
                logger.debug("OpenStack driver available")
            except Exception as e:
                logger.warning(f"OpenStack driver not functional: {e}")
        
        return available
    
    def validate_driver(self, infrastructure: str) -> bool:
        """
        Valida si un driver está disponible y funcionando.
        
        Args:
            infrastructure: Tipo de infraestructura a validar
            
        Returns:
            bool: True si el driver está disponible y funcional
        """
        try:
            driver = self.select_driver(infrastructure)
            
            # Test básico del driver
            if hasattr(driver, 'driver_name'):
                logger.info(f"✓ {infrastructure} driver validation passed: {driver.driver_name}")
                return True
            else:
                logger.warning(f"Driver {infrastructure} missing required attributes")
                return False
                
        except Exception as e:
            logger.error(f"✗ {infrastructure} driver validation failed: {e}")
            return False
    
    def clear_driver_cache(self):
        """Limpia el cache de drivers."""
        self._driver_cache.clear()
        logger.info("Driver cache cleared")
