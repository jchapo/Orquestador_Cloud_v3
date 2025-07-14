#!/bin/bash
# Script para encontrar de dónde vienen los nombres pucp-serverX

echo "🔍 Rastreando origen de nombres 'pucp-serverX'..."
echo ""

# 1. Buscar en archivos de configuración
echo "📁 1. Buscando en archivos de configuración..."
find /opt/pucp-orchestrator -name "*.json" -exec grep -l "pucp-server" {} \; 2>/dev/null || echo "   No encontrados en .json"
find /opt/pucp-orchestrator -name "*.yaml" -exec grep -l "pucp-server" {} \; 2>/dev/null || echo "   No encontrados en .yaml"
find /opt/pucp-orchestrator -name "*.yml" -exec grep -l "pucp-server" {} \; 2>/dev/null || echo "   No encontrados en .yml"
find /opt/pucp-orchestrator -name "*.conf" -exec grep -l "pucp-server" {} \; 2>/dev/null || echo "   No encontrados en .conf"

echo ""

# 2. Buscar en código Python
echo "🐍 2. Buscando en código Python..."
find /opt/pucp-orchestrator -name "*.py" -exec grep -l "pucp-server" {} \; 2>/dev/null

echo ""

# 3. Verificar cluster_config.json específicamente
echo "📋 3. Verificando cluster_config.json..."
CONFIG_FILE="/opt/pucp-orchestrator/cluster_config.json"
if [ -f "$CONFIG_FILE" ]; then
    echo "   ✅ Archivo encontrado: $CONFIG_FILE"
    echo "   📄 Contenido:"
    cat "$CONFIG_FILE" | jq . 2>/dev/null || cat "$CONFIG_FILE"
else
    echo "   ❌ Archivo NO encontrado: $CONFIG_FILE"
fi

echo ""

# 4. Buscar otros archivos de configuración posibles
echo "🔎 4. Buscando otros archivos de configuración..."
find /opt/pucp-orchestrator -name "*cluster*" -type f 2>/dev/null
find /opt/pucp-orchestrator -name "*config*" -type f 2>/dev/null | head -10

echo ""

# 5. Verificar variables de entorno
echo "🌍 5. Verificando variables de entorno del proceso..."
if pgrep -f "slice_service" > /dev/null; then
    PID=$(pgrep -f "slice_service")
    echo "   PID del proceso: $PID"
    echo "   Variables de entorno relevantes:"
    cat /proc/$PID/environ 2>/dev/null | tr '\0' '\n' | grep -i "server\|cluster\|pucp" || echo "   No encontradas"
else
    echo "   ⚠️  Proceso slice_service no está corriendo"
fi

echo ""

# 6. Buscar en logs recientes
echo "📋 6. Buscando en logs recientes..."
echo "   Logs de slice-service con 'pucp-server':"
journalctl -u pucp-slice-service --since "1 hour ago" | grep "pucp-server" | tail -5 || echo "   No encontrados en logs recientes"

echo ""

# 7. Verificar función load_cluster_config
echo "🔧 7. Verificando función load_cluster_config en el código..."
grep -A 10 -B 5 "load_cluster_config" /opt/pucp-orchestrator/slice_service/__init__.py 2>/dev/null || echo "   Función no encontrada"

echo ""
echo "🎯 CONCLUSIONES:"
echo "   - Si cluster_config.json existe y contiene 'pucp-serverX', ahí está el origen"
echo "   - Si no existe, los nombres vienen del código Python directamente"
echo "   - Revisa los archivos encontrados arriba para identificar la fuente"
