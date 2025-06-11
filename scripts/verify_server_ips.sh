#!/bin/bash
# scripts/verify_server_ips.sh

echo "=== Verificación de IPs del Cluster Linux ==="

# IPs del documento del proyecto
MANAGEMENT_SUBNET="192.168.201.0/24"  # LC 1 (MGMT) para Linux Cluster
CLUSTER_SUBNET="10.60.1.0/24"         # Asignado al Grupo 1

echo "Subredes del proyecto:"
echo "  - Management Linux Cluster: $MANAGEMENT_SUBNET"
echo "  - Cluster Linux (Grupo 1): $CLUSTER_SUBNET"
echo ""

# Función para verificar una IP
check_ip() {
    local ip=$1
    local name=$2
    
    printf "%-10s %-15s " "$name" "$ip"
    
    if ping -c 1 -W 2 $ip >/dev/null 2>&1; then
        echo "✅ RESPONDE"
        
        # Intentar obtener hostname
        hostname=$(ssh -o ConnectTimeout=3 -o BatchMode=yes root@$ip "hostname" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "           Hostname: $hostname"
        fi
        
        # Verificar si tiene KVM
        kvm_check=$(ssh -o ConnectTimeout=3 -o BatchMode=yes root@$ip "which qemu-kvm" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "           KVM: ✅ Instalado"
        else
            echo "           KVM: ❌ No encontrado"
        fi
        
    else
        echo "❌ NO RESPONDE"
    fi
    echo ""
}

# Verificar IPs actuales del script
echo "Verificando IPs configuradas en el script:"
SERVERS=("server1:10.60.1.11" "server2:10.60.1.12" "server3:10.60.1.13" "server4:10.60.1.14")

for server in "${SERVERS[@]}"; do
    server_name=$(echo $server | cut -d: -f1)
    server_ip=$(echo $server | cut -d: -f2)
    check_ip $server_ip $server_name
done

echo "=== Escaneo de red para encontrar servidores ==="

# Escanear subnet de management
echo "Escaneando subnet de management (192.168.201.0/24)..."
for i in {1..20}; do
    ip="192.168.201.$i"
    if ping -c 1 -W 1 $ip >/dev/null 2>&1; then
        hostname=$(timeout 3 ssh -o ConnectTimeout=2 -o BatchMode=yes root@$ip "hostname" 2>/dev/null || echo "unknown")
        echo "  $ip - $hostname"
    fi
done

# Escanear subnet del cluster
echo ""
echo "Escaneando subnet del cluster (10.60.1.0/24)..."
for i in {1..20}; do
    ip="10.60.1.$i"
    if ping -c 1 -W 1 $ip >/dev/null 2>&1; then
        hostname=$(timeout 3 ssh -o ConnectTimeout=2 -o BatchMode=yes root@$ip "hostname" 2>/dev/null || echo "unknown")
        echo "  $ip - $hostname"
    fi
done

echo ""
echo "=== Información de red local ==="
echo "Interfaces de red:"
ip addr show | grep -E "(inet|UP|DOWN)" | grep -v 127.0.0.1

echo ""
echo "Rutas:"
ip route