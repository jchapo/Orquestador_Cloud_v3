#!/bin/bash

echo "🔍 Diagnóstico detallado de OpenStack"
echo "===================================="

# 1. Verificar túneles SSH
echo "=== 1. Túneles SSH activos ==="
ps aux | grep "ssh.*5000" | grep -v grep
echo ""

# 2. Verificar puertos locales
echo "=== 2. Puertos locales escuchando ==="
netstat -tlnp | grep -E "(5000|8774|9292|9696)"
echo ""

# 3. Probar conectividad HTTP
echo "=== 3. Conectividad HTTP ==="
for port in 5000 8774 9292 9696; do
    echo "Probando localhost:$port..."
    if curl -s -m 5 http://localhost:$port > /dev/null; then
        echo "  ✅ Puerto $port responde"
    else
        echo "  ❌ Puerto $port no responde"
    fi
done
echo ""

# 4. Verificar respuesta de Keystone
echo "=== 4. Respuesta de Keystone ==="
echo "GET http://localhost:5000:"
curl -s -m 5 http://localhost:5000 || echo "Sin respuesta"
echo ""
echo "GET http://localhost:5000/v3:"
curl -s -m 5 http://localhost:5000/v3 || echo "Sin respuesta"
echo ""

# 5. Probar acceso directo al gateway
echo "=== 5. Acceso directo via Gateway ==="
echo "Probando acceso directo a 10.60.2.21:5000 via gateway..."
ssh -o ConnectTimeout=10 ubuntu@10.20.12.187 -p 5821 "curl -s -m 5 http://10.60.2.21:5000/v3" 2>/dev/null || echo "Sin acceso directo"
echo ""

# 6. Verificar configuración OpenStack
echo "=== 6. Configuración OpenStack ==="
if [ -f "/opt/pucp-orchestrator/openstack_cluster_config.json" ]; then
    echo "Archivo de configuración encontrado:"
    cat /opt/pucp-orchestrator/openstack_cluster_config.json | jq .auth 2>/dev/null || echo "Sin jq, mostrando raw:"
    grep -A 10 '"auth"' /opt/pucp-orchestrator/openstack_cluster_config.json
else
    echo "❌ Archivo de configuración no encontrado"
fi
