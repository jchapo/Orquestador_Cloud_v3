class Orchestrator:
    def __init__(self):
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
                from .drivers.linux_driver import LinuxClusterDriver
                driver = LinuxClusterDriver(token=token)
                logger.info(f"✓ Linux driver initialized with token: {'Yes' if token else 'No'}")
                
            elif infrastructure == 'openstack':
                from .drivers.openstack_driver import OpenStackDriver
                driver = OpenStackDriver(token=token)
                logger.info(f"✓ OpenStack driver initialized with token: {'Yes' if token else 'No'}")
                
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
            from .drivers.linux_driver import LinuxClusterDriver
            available.append('linux')
            logger.debug("Linux driver available")
        except ImportError:
            logger.warning("Linux driver not available")
        
        # Test OpenStack driver  
        try:
            from .drivers.openstack_driver import OpenStackDriver
            available.append('openstack')
            logger.debug("OpenStack driver available")
        except ImportError:
            logger.warning("OpenStack driver not available")
        
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
            if hasattr(driver, 'get_infrastructure_type'):
                assert driver.get_infrastructure_type() == infrastructure
                
            if hasattr(driver, 'get_available_resources'):
                resources = driver.get_available_resources()
                assert isinstance(resources, dict)
                
            logger.info(f"✓ {infrastructure} driver validation passed")
            return True
            
        except Exception as e:
            logger.error(f"✗ {infrastructure} driver validation failed: {e}")
            return False
    
    def clear_driver_cache(self):
        """Limpia el cache de drivers."""
        self._driver_cache.clear()
        logger.info("Driver cache cleared")