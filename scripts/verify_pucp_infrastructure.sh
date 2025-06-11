#!/bin/bash
"""
Verificar acceso a la infraestructura real PUCP a través de VPN
"""

echo "=== Verificación de Infraestructura PUCP Real ==="

# Según tu documento del proyecto
GATEWAY_NODE="gateway"  # Nodo gateway accesible desde PUCP
APP_NODE="app"          # Nodo app (donde estás ejecutando)

# IPs del proyecto según el documento
CLUSTER_LINUX_IPS=("10.60.1.11" "10.60.1.12" "10.60.1.13" "10.60.1.14")
CLUSTER_OPENSTACK_IPS=("10.60.2.21" "10.60.2.22" "10.60.2.23" "10.60.2.24")
GATEWAY_IP="10.60.1.1"  # O la IP real del gateway

# Puertos de acceso según tu documento
declare -A SERVER_PORTS=(
    ["server1"]="5811"
    ["server2"]="5812" 
    ["server3"]="5813"
    ["server4"]="5814"
    ["ovs1"]="5815"
    ["headnode"]="5821"
    ["worker1"]="5822"
    ["worker2"]="5823"
    ["worker3"]="5824"
    ["ovs2"]="5825"
)

echo "Estado actual:"
echo "  - Nodo actual: $(hostname) ($(hostname -I | awk '{print $1}'))"
echo "  - Red actual: $(ip route | grep default | awk '{print $3}' | head -1)"
echo ""

# Función para verificar conectividad VPN
check_vpn_access() {
    echo "=== Verificando acceso VPN ==="
    
    echo "1. Verificando conectividad al gateway..."
    if ping -c 3 -W 5 $GATEWAY_IP >/dev/null 2>&1; then
        echo "✅ Gateway ($GATEWAY_IP) accesible"
        
        # Verificar si es realmente el gateway del proyecto
        echo "2. Verificando identidad del gateway..."
        gateway_info=$(timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes root@$GATEWAY_IP "hostname; uname -a" 2>/dev/null || echo "No SSH access")
        echo "   Gateway info: $gateway_info"
        
    else
        echo "❌ Gateway ($GATEWAY_IP) no accesible"
        echo ""
        echo "Posibles problemas:"
        echo "  1. No estás conectado a la VPN de la PUCP"
        echo "  2. La topología final no está desplegada"
        echo "  3. IP del gateway incorrecta"
        echo ""
        return 1
    fi
}

# Función para verificar acceso a servidores del cluster Linux
check_linux_cluster() {
    echo ""
    echo "=== Verificando Cluster Linux ==="
    
    accessible_servers=()
    
    for i in "${!CLUSTER_LINUX_IPS[@]}"; do
        server_name="server$((i+1))"
        server_ip="${CLUSTER_LINUX_IPS[i]}"
        server_port="${SERVER_PORTS[$server_name]}"
        
        echo "Verificando $server_name ($server_ip)..."
        
        # Verificar ping directo
        if ping -c 1 -W 2 $server_ip >/dev/null 2>&1; then
            echo "  ✅ Ping directo OK"
            accessible_servers+=("$server_name:$server_ip")
        else
            echo "  ❌ Ping directo falló"
            
            # Verificar acceso a través del gateway con puerto mapeado
            echo "  Probando acceso vía gateway:$server_port..."
            if timeout 5 nc -z $GATEWAY_IP $server_port 2>/dev/null; then
                echo "  ✅ Acceso vía gateway:$server_port OK"
                accessible_servers+=("$server_name:$GATEWAY_IP:$server_port")
            else
                echo "  ❌ Acceso vía gateway:$server_port falló"
            fi
        fi
    done
    
    echo ""
    echo "Servidores Linux accesibles: ${#accessible_servers[@]}/4"
    for server in "${accessible_servers[@]}"; do
        echo "  - $server"
    done
}

# Función para verificar acceso a cluster OpenStack
check_openstack_cluster() {
    echo ""
    echo "=== Verificando Cluster OpenStack ==="
    
    openstack_nodes=("headnode" "worker1" "worker2" "worker3")
    accessible_nodes=()
    
    for i in "${!CLUSTER_OPENSTACK_IPS[@]}"; do
        node_name="${openstack_nodes[i]}"
        node_ip="${CLUSTER_OPENSTACK_IPS[i]}"
        node_port="${SERVER_PORTS[$node_name]}"
        
        echo "Verificando $node_name ($node_ip)..."
        
        if ping -c 1 -W 2 $node_ip >/dev/null 2>&1; then
            echo "  ✅ Ping directo OK"
            accessible_nodes+=("$node_name:$node_ip")
        else
            echo "  ❌ Ping directo falló"
            
            # Verificar acceso vía gateway
            if timeout 5 nc -z $GATEWAY_IP $node_port 2>/dev/null; then
                echo "  ✅ Acceso vía gateway:$node_port OK"
                accessible_nodes+=("$node_name:$GATEWAY_IP:$node_port")
            else
                echo "  ❌ Acceso vía gateway:$node_port falló"
            fi
        fi
    done
    
    echo ""
    echo "Nodos OpenStack accesibles: ${#accessible_nodes[@]}/4"
    for node in "${accessible_nodes[@]}"; do
        echo "  - $node"
    done
}

# Función para generar configuración actualizada
generate_real_config() {
    echo ""
    echo "=== Generando Configuración para Infraestructura Real ==="
    
    # Determinar método de acceso basado en la verificación
    if ping -c 1 -W 2 ${CLUSTER_LINUX_IPS[0]} >/dev/null 2>&1; then
        access_method="direct"
        echo "Método de acceso: Directo a IPs de cluster"
    else
        access_method="gateway_proxy"
        echo "Método de acceso: A través de gateway con puertos mapeados"
    fi
    
    cat > /opt/pucp-orchestrator/pucp_real_infrastructure.json << EOF
{
    "infrastructure_type": "pucp_real",
    "access_method": "$access_method",
    "gateway": {
        "ip": "$GATEWAY_IP",
        "accessible_from_pucp": true
    },
    "linux_cluster": {
        "network_range": "10.60.1.0/24",
        "servers": {
            "server1": {
                "ip": "${CLUSTER_LINUX_IPS[0]}",
                "gateway_port": "${SERVER_PORTS[server1]}",
                "uri": "qemu+ssh://root@${CLUSTER_LINUX_IPS[0]}/system",
                "max_vcpus": 8,
                "max_ram": 16384,
                "max_disk": 100
            },
            "server2": {
                "ip": "${CLUSTER_LINUX_IPS[1]}",
                "gateway_port": "${SERVER_PORTS[server2]}",
                "uri": "qemu+ssh://root@${CLUSTER_LINUX_IPS[1]}/system",
                "max_vcpus": 8,
                "max_ram": 16384,
                "max_disk": 100
            },
            "server3": {
                "ip": "${CLUSTER_LINUX_IPS[2]}",
                "gateway_port": "${SERVER_PORTS[server3]}",
                "uri": "qemu+ssh://root@${CLUSTER_LINUX_IPS[2]}/system",
                "max_vcpus": 8,
                "max_ram": 16384,
                "max_disk": 100
            },
            "server4": {
                "ip": "${CLUSTER_LINUX_IPS[3]}",
                "gateway_port": "${SERVER_PORTS[server4]}",
                "uri": "qemu+ssh://root@${CLUSTER_LINUX_IPS[3]}/system",
                "max_vcpus": 8,
                "max_ram": 16384,
                "max_disk": 100
            }
        }
    },
    "openstack_cluster": {
        "network_range": "10.60.2.0/24",
        "nodes": {
            "headnode": {
                "ip": "${CLUSTER_OPENSTACK_IPS[0]}",
                "gateway_port": "${SERVER_PORTS[headnode]}",
                "role": "controller"
            },
            "worker1": {
                "ip": "${CLUSTER_OPENSTACK_IPS[1]}",
                "gateway_port": "${SERVER_PORTS[worker1]}",
                "role": "compute"
            },
            "worker2": {
                "ip": "${CLUSTER_OPENSTACK_IPS[2]}",
                "gateway_port": "${SERVER_PORTS[worker2]}",
                "role": "compute"
            },
            "worker3": {
                "ip": "${CLUSTER_OPENSTACK_IPS[3]}",
                "gateway_port": "${SERVER_PORTS[worker3]}",
                "role": "compute"
            }
        }
    },
    "network_config": {
        "ovs_switches": {
            "ovs1": {"port": "${SERVER_PORTS[ovs1]}", "cluster": "linux"},
            "ovs2": {"port": "${SERVER_PORTS[ovs2]}", "cluster": "openstack"}
        }
    },
    "verified_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
    
    echo "✅ Configuración guardada en: /opt/pucp-orchestrador/pucp_real_infrastructure.json"
}

# Función principal
main() {
    echo "Iniciando verificación de infraestructura PUCP..."
    echo ""
    
    # Verificar prerrequisitos
    echo "=== Verificando Prerrequisitos ==="
    
    if ! command -v nc >/dev/null; then
        echo "Instalando netcat..."
        sudo apt update && sudo apt install -y netcat-openbsd
    fi
    
    echo "✅ Herramientas disponibles"
    echo ""
    
    # Ejecutar verificaciones
    if check_vpn_access; then
        check_linux_cluster
        check_openstack_cluster
        generate_real_config
        
        echo ""
        echo "=== Instrucciones Siguientes ==="
        echo "1. Si tienes acceso a servidores, ejecutar:"
        echo "   ./setup_pucp_real_cluster.sh"
        echo ""
        echo "2. Si no tienes acceso completo:"
        echo "   - Verificar conexión VPN a PUCP"
        echo "   - Contactar administrador del VNRT"
        echo "   - Verificar que la topología esté desplegada"
        
    else
        echo ""
        echo "=== Acciones Requeridas ==="
        echo "1. **Conectar a VPN de la PUCP**"
        echo "   - Usar cliente VPN institucional"
        echo "   - Verificar credenciales"
        echo ""
        echo "2. **Verificar acceso al VNRT**"
        echo "   - Contactar administrador del laboratorio"
        echo "   - Verificar permisos de acceso"
        echo ""
        echo "3. **Verificar topología desplegada**"
        echo "   - La topología final debe estar activa"
        echo "   - Gateway y servidores deben estar corriendo"
    fi
}

# Ejecutar verificación
main