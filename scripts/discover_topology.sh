#!/bin/bash
# scripts/discover_topology.sh

echo "=== Descubrimiento de Topología PUCP ==="

# Según tu documento del proyecto
echo "Topología esperada del proyecto:"
echo "  - Gateway PUCP: acceso desde universidad"
echo "  - Linux Cluster: 4 servidores (server1-4)"
echo "  - OpenStack Cluster: 4 nodos (headnode, worker1-3)"
echo "  - OVS switches: ovs1 (Linux), ovs2 (OpenStack)"
echo ""

# Verificar desde dónde estamos ejecutando
echo "=== Información del nodo actual ==="
echo "Hostname: $(hostname)"
echo "IP addresses:"
ip addr show | grep "inet " | grep -v 127.0.0.1

echo ""
echo "=== Verificando conectividad a gateway ==="
# El gateway debería ser accesible según tu documento
GATEWAY_IPS=("10.60.1.1" "192.168.201.1" "192.168.202.1")

for gw in "${GATEWAY_IPS[@]}"; do
    if ping -c 1 -W 2 $gw >/dev/null 2>&1; then
        echo "✅ Gateway $gw responde"
    else
        echo "❌ Gateway $gw no responde"
    fi
done

echo ""
echo "=== Buscando nodos del Linux Cluster ==="

# Buscar en diferentes rangos posibles
POSSIBLE_RANGES=("10.60.1" "192.168.201" "192.168.100")

for range in "${POSSIBLE_RANGES[@]}"; do
    echo "Escaneando $range.0/24..."
    found_hosts=()
    
    for i in {10..50}; do
        ip="$range.$i"
        if ping -c 1 -W 1 $ip >/dev/null 2>&1; then
            found_hosts+=("$ip")
        fi
    done
    
    if [ ${#found_hosts[@]} -gt 0 ]; then
        echo "  Hosts encontrados en $range.0/24:"
        for host in "${found_hosts[@]}"; do
            # Intentar obtener info del host
            hostname=$(timeout 2 ssh -o ConnectTimeout=1 -o BatchMode=yes root@$host "hostname" 2>/dev/null || echo "unknown")
            os_info=$(timeout 2 ssh -o ConnectTimeout=1 -o BatchMode=yes root@$host "uname -s" 2>/dev/null || echo "unknown")
            echo "    $host - $hostname ($os_info)"
        done
    else
        echo "  No se encontraron hosts en $range.0/24"
    fi
    echo ""
done