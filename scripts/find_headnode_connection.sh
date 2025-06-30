#!/bin/bash

echo "🔍 Buscando cómo conectar al headnode con OpenStack..."

GATEWAY_IP="10.20.12.187"

echo "1. Probando conexión directa desde gateway al headnode interno..."
ssh ubuntu@$GATEWAY_IP -p 5821 << 'REMOTE_SCRIPT'
echo "=== Desde gateway, buscando headnode ==="

echo "1. Verificando IPs en red interna:"
ip addr show | grep -E "(192\.168\.202|10\.60\.2)"

echo ""
echo "2. Probando conectividad a headnode por IP interna:"
for ip in 192.168.202.1 10.60.2.21; do
    echo "Probando IP $ip:"
    if ping -c 1 $ip >/dev/null 2>&1; then
        echo "  ✅ $ip: RESPONDE"
        
        # Probar SSH al headnode
        if ssh -o ConnectTimeout=5 -o BatchMode=yes ubuntu@$ip "echo 'Conectado al headnode real'" 2>/dev/null; then
            echo "  ✅ SSH funciona a $ip"
            
            # Verificar servicios OpenStack en el headnode
            ssh ubuntu@$ip << 'HEADNODE_CHECK'
echo "    Hostname: $(hostname)"
echo "    Servicios OpenStack:"
systemctl is-active apache2 nova-api neutron-server glance-api 2>/dev/null || echo "    Error verificando servicios"
echo "    Puertos OpenStack:"
netstat -tlnp | grep -E "(5000|8774|9292|9696)" | head -3 2>/dev/null || echo "    No hay puertos OpenStack"
HEADNODE_CHECK
        else
            echo "  ❌ SSH no funciona a $ip"
        fi
    else
        echo "  ❌ $ip: NO RESPONDE"
    fi
done

echo ""
echo "3. Verificando procesos/tunnels en gateway:"
ps aux | grep -E "(ssh|tunnel)" | grep -v grep | head -3
REMOTE_SCRIPT
