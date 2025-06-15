#!/bin/bash
# scripts/fix_network_database.sh

echo "🌐 Reparando Network Service Database..."

cd /opt/pucp-orchestrator/network_service

# Verificar si el archivo existe
if [ ! -f "network_service.db" ]; then
    echo "⚠️ Base de datos network_service.db no existe"
    echo "🔧 Creando base de datos..."
    
    # Activar entorno virtual
    source /opt/pucp-orchestrator/venv/bin/activate
    
    # Crear BD ejecutando el init
    python3 -c "
import sys
sys.path.append('/opt/pucp-orchestrator')
from network_service.network_service import init_db
init_db()
print('✅ Base de datos network_service creada')
"
    
    if [ -f "network_service.db" ]; then
        echo "✅ Base de datos creada exitosamente"
    else
        echo "❌ Error creando base de datos"
    fi
else
    echo "✅ Base de datos network_service existe"
fi

# Verificar permisos
chmod 664 network_service.db 2>/dev/null || true
echo "✅ Permisos ajustados"
