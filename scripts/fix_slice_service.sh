#!/bin/bash
# scripts/fix_slice_service.sh

echo "🔧 Reparando Slice Service..."

# Verificar errores en slice_service
echo "📋 Verificando errores..."
sudo journalctl -u pucp-slice-service --since '10 minutes ago' --no-pager

echo ""
echo "🔍 Verificando archivo de servicio..."
if [ -f "/opt/pucp-orchestrator/slice_service/slice_service.py" ]; then
    echo "✅ Archivo principal existe"
    
    # Probar sintaxis Python
    cd /opt/pucp-orchestrator
    source venv/bin/activate
    
    echo "🐍 Verificando sintaxis Python..."
    python3 -m py_compile slice_service/slice_service.py
    
    if [ $? -eq 0 ]; then
        echo "✅ Sintaxis Python correcta"
        
        # Verificar imports
        echo "📦 Verificando imports..."
        python3 -c "
import sys
sys.path.append('/opt/pucp-orchestrator')
try:
    from slice_service import slice_service
    print('✅ Imports correctos')
except ImportError as e:
    print(f'❌ Error de import: {e}')
except Exception as e:
    print(f'❌ Error: {e}')
"
    else
        echo "❌ Error de sintaxis Python"
    fi
else
    echo "❌ Archivo slice_service.py no encontrado"
fi

# Verificar base de datos
echo ""
echo "💾 Verificando base de datos..."
if [ -f "/opt/pucp-orchestrator/slice_service/slice_service.db" ]; then
    echo "✅ Base de datos existe"
    
    # Test de SQLite
    if sqlite3 "/opt/pucp-orchestrator/slice_service/slice_service.db" ".schema" >/dev/null 2>&1; then
        echo "✅ Base de datos accesible"
        
        # Mostrar tablas
        echo "📊 Tablas en la BD:"
        sqlite3 "/opt/pucp-orchestrator/slice_service/slice_service.db" ".tables" | sed 's/^/   /'
    else
        echo "❌ Base de datos corrupta"
        echo "🔧 Recreando base de datos..."
        rm -f "/opt/pucp-orchestrator/slice_service/slice_service.db"
    fi
else
    echo "⚠️ Base de datos no existe - se creará automáticamente"
fi

# Intentar iniciar manualmente
echo ""
echo "🚀 Intentando iniciar slice_service manualmente..."
cd /opt/pucp-orchestrator/slice_service
timeout 10 python3 slice_service.py &
SERVICE_PID=$!

sleep 3

if ps -p $SERVICE_PID > /dev/null; then
    echo "✅ Slice service arrancó correctamente"
    kill $SERVICE_PID
    
    # Reiniciar servicio systemd
    echo "🔄 Reiniciando servicio systemd..."
    sudo systemctl stop pucp-slice-service
    sleep 2
    sudo systemctl start pucp-slice-service
    sleep 3
    
    if systemctl is-active pucp-slice-service >/dev/null; then
        echo "✅ Slice service systemd funcionando"
    else
        echo "❌ Slice service systemd aún tiene problemas"
        sudo journalctl -u pucp-slice-service --since '1 minute ago' --no-pager
    fi
else
    echo "❌ Slice service no pudo arrancar"
    echo "📋 Revisa los logs arriba para errores específicos"
fi

echo ""
echo "🏁 Diagnóstico de Slice Service completado"
