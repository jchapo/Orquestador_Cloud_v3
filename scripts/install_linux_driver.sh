#!/bin/bash
"""
Instalación completa del Linux Driver
"""

set -e

echo "=== Instalando Linux Driver para PUCP Orchestrator ==="

# Verificar que estamos en el directorio correcto
if [ ! -f "slice_service/slice_service.py" ]; then
    echo "Error: Ejecutar desde el directorio raíz del orchestrator"
    exit 1
fi

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias Python
echo "Instalando dependencias Python..."
pip install libvirt-python==8.0.0 paramiko==3.4.0

# Crear directorio de drivers si no existe
mkdir -p slice_service/drivers

# Verificar que los archivos del driver existen
if [ ! -f "slice_service/drivers/linux_driver.py" ]; then
    echo "Error: linux_driver.py no encontrado"
    echo "Asegúrate de haber copiado todos los archivos del driver"
    exit 1
fi

# Hacer ejecutables los scripts
chmod +x scripts/setup_linux_cluster.sh
chmod +x scripts/test_linux_driver.py

# Crear archivo __init__.py en drivers
cat > slice_service/drivers/__init__.py << 'EOF'
"""
PUCP Cloud Orchestrator - Infrastructure Drivers
"""

from .base_driver import BaseDriver
from .linux_driver import LinuxClusterDriver

__all__ = ['BaseDriver', 'LinuxClusterDriver']
EOF

# Actualizar configuración del sistema
echo "Configurando sistema..."

# Crear directorio de logs si no existe
sudo mkdir -p /var/log/pucp-orchestrator
sudo chown $USER:$USER /var/log/pucp-orchestrator

# Crear directorio para claves SSH
sudo mkdir -p /opt/pucp-orchestrator/keys
sudo chown $USER:$USER /opt/pucp-orchestrador/keys

# Instalar libvirt client tools en el orchestrator
echo "Instalando herramientas libvirt..."
sudo apt update
sudo apt install -y libvirt-clients qemu-utils openssh-client

echo "✅ Linux Driver instalado correctamente!"
echo ""
echo "Próximos pasos:"
echo "1. Ejecutar: sudo ./scripts/setup_linux_cluster.sh"
echo "2. Reiniciar slice_service"
echo "3. Probar con: python3 scripts/test_linux_driver.py"