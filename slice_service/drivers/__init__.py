"""
PUCP Cloud Orchestrator - Infrastructure Drivers
"""

from .base_driver import BaseDriver

# Importar drivers disponibles
_available_drivers = {}

try:
    from .linux_driver import LinuxClusterDriver
    _available_drivers['linux'] = LinuxClusterDriver
    __all__ = ['BaseDriver', 'LinuxClusterDriver']
except ImportError as e:
    print(f"Warning: LinuxClusterDriver not available: {e}")
    __all__ = ['BaseDriver']

try:
    from .openstack_driver import OpenStackDriver
    _available_drivers['openstack'] = OpenStackDriver
    __all__.append('OpenStackDriver')
except ImportError as e:
    print(f"Warning: OpenStackDriver not available: {e}")

def get_available_drivers():
    """Retorna diccionario de drivers disponibles"""
    return _available_drivers.copy()

def is_driver_available(infrastructure: str) -> bool:
    """Verifica si un driver está disponible"""
    return infrastructure in _available_drivers