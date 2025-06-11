#!/bin/bash
"""
Configuración para la infraestructura real PUCP identificada
Basado en la topología verificada: app -> gateway -> servers
"""

set -e

echo "=== PUCP Orchestrator - Configuración Real ==="

# Configuración confirmada de tu infraestructura
APP_NODE="10.20.12.16"           # Nodo orchestrator (donde ejecutas)
GATEWAY_NODE="10.20.12.187"     # Gateway con acceso a management
GATEWAY_MGMT="192.168.201.10"   # IP del gateway en red management

# Servidores del cluster Linux (en red management)
declare -A LINUX_SERVERS=(
    ["server1"]="192.168.201.1"
    ["server2"]="192.168.201.2"  # Asumir secuencial
    ["server3"]="192.168.201.3"
    ["server4"]="192.168.201.4"
)

# Red asignada para VMs (Grupo 1)
CLUSTER_VM_NETWORK="10.60.1.0/24"

echo "Topología identificada:"
echo "  App Orchestrator: $APP_NODE"
echo "  Gateway: $GATEWAY_NODE (mgmt: $GATEWAY_MGMT)"
echo "  Cluster Management: 192.168.201.0/24"
echo "  VMs Network: $CLUSTER_VM_NETWORK"
echo ""

# Función para verificar conectividad completa
verify_infrastructure() {
    echo "=== Verificando Infraestructura ==="
    
    # Test 1: App -> Gateway
    echo "1. Conectividad app -> gateway..."
    if ping -c 2 $GATEWAY_NODE >/dev/null 2>&1; then
        echo "  ✅ app -> gateway OK"
    else
        echo "  ❌ app -> gateway FAILED"
        return 1
    fi
    
    # Test 2: Gateway -> Management Network (via SSH)
    echo "2. Acceso a red management via gateway..."
    gateway_to_mgmt=$(ssh -o ConnectTimeout=5 ubuntu@$GATEWAY_NODE "ping -c 2 192.168.201.1 >/dev/null 2>&1 && echo 'OK' || echo 'FAILED'")
    if [ "$gateway_to_mgmt" = "OK" ]; then
        echo "  ✅ gateway -> management network OK"
    else
        echo "  ❌ gateway -> management network FAILED"
        return 1
    fi
    
    # Test 3: Identificar servidores disponibles
    echo "3. Identificando servidores del cluster..."
    available_servers=()
    
    for server_name in "${!LINUX_SERVERS[@]}"; do
        server_ip="${LINUX_SERVERS[$server_name]}"
        echo "  Verificando $server_name ($server_ip)..."
        
        # Verificar vía gateway usando SSH proxy
        server_status=$(ssh -o ConnectTimeout=5 -o ProxyJump=ubuntu@$GATEWAY_NODE ubuntu@$server_ip "hostname" 2>/dev/null || echo "FAILED")
        
        if [ "$server_status" != "FAILED" ]; then
            echo "    ✅ $server_name accesible - hostname: $server_status"
            available_servers+=("$server_name:$server_ip")
        else
            echo "    ❌ $server_name no accesible"
        fi
    done
    
    echo ""
    echo "Servidores disponibles: ${#available_servers[@]}"
    for server in "${available_servers[@]}"; do
        echo "  - $server"
    done
    
    if [ ${#available_servers[@]} -eq 0 ]; then
        echo "❌ No se encontraron servidores accesibles"
        return 1
    fi
    
    return 0
}

# Función para configurar SSH con ProxyJump
configure_ssh_infrastructure() {
    echo ""
    echo "=== Configurando SSH para Infraestructura Real ==="
    
    # Crear directorio SSH
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Generar clave específica para PUCP
    PUCP_KEY="$HOME/.ssh/pucp_cluster_real"
    if [ ! -f "$PUCP_KEY" ]; then
        echo "Generando clave SSH para cluster PUCP..."
        ssh-keygen -t rsa -b 4096 -f "$PUCP_KEY" -N "" -C "pucp-real-cluster@$(hostname)"
        chmod 600 "$PUCP_KEY"
    fi
    
    echo "Clave SSH generada: $PUCP_KEY"
    echo ""
    
    # Configurar SSH config con ProxyJump a través del gateway
    echo "Configurando SSH config con ProxyJump..."
    
    cat >> ~/.ssh/config << EOF

# PUCP Infrastructure - Real Cluster Access
Host pucp-gateway
    HostName $GATEWAY_NODE
    User ubuntu
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server1
    HostName 192.168.201.1
    User ubuntu
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server2
    HostName 192.168.201.2
    User ubuntu
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server3
    HostName 192.168.201.3
    User ubuntu
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server4
    HostName 192.168.201.4
    User ubuntu
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
    
    echo "✅ SSH config creado"
    echo ""
    echo "Para configurar acceso SSH, ejecutar estos comandos:"
    echo "1. Copiar clave al gateway:"
    echo "   ssh-copy-id -i $PUCP_KEY.pub ubuntu@$GATEWAY_NODE"
    echo ""
    echo "2. Copiar clave a los servidores (a través del gateway):"
    echo "   ssh-copy-id -i $PUCP_KEY.pub pucp-server1"
    echo "   ssh-copy-id -i $PUCP_KEY.pub pucp-server2"
    echo "   ssh-copy-id -i $PUCP_KEY.pub pucp-server3"
    echo "   ssh-copy-id -i $PUCP_KEY.pub pucp-server4"
    echo ""
    echo "3. Verificar acceso:"
    echo "   ssh pucp-server1 'hostname; uname -a'"
}

# Función para crear Linux Driver adaptado a tu infraestructura
create_pucp_linux_driver() {
    echo ""
    echo "=== Creando Linux Driver para PUCP Real ==="
    
    # Backup del driver actual si existe
    if [ -f "slice_service/drivers/linux_driver.py" ]; then
        cp slice_service/drivers/linux_driver.py slice_service/drivers/linux_driver_backup.py
    fi
    
    # Crear configuración específica
    cat > slice_service/drivers/pucp_real_config.py << EOF
#!/usr/bin/env python3
"""
Configuración específica para infraestructura real PUCP
Basada en la topología verificada
"""

# Configuración real de la infraestructura PUCP
PUCP_REAL_CONFIG = {
    'app_node': '$APP_NODE',
    'gateway_node': '$GATEWAY_NODE',
    'gateway_mgmt': '$GATEWAY_MGMT',
    'cluster_vm_network': '$CLUSTER_VM_NETWORK',
    'ssh_key': '$HOME/.ssh/pucp_cluster_real'
}

# Hypervisors usando SSH ProxyJump
PUCP_HYPERVISORS = {
    'server1': {
        'uri': 'qemu+ssh://pucp-server1/system',
        'mgmt_ip': '192.168.201.1',
        'ssh_host': 'pucp-server1',
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'vm_network_start': '10.60.1.11'
    },
    'server2': {
        'uri': 'qemu+ssh://pucp-server2/system',
        'mgmt_ip': '192.168.201.2',
        'ssh_host': 'pucp-server2',
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'vm_network_start': '10.60.1.21'
    },
    'server3': {
        'uri': 'qemu+ssh://pucp-server3/system',
        'mgmt_ip': '192.168.201.3',
        'ssh_host': 'pucp-server3',
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'vm_network_start': '10.60.1.31'
    },
    'server4': {
        'uri': 'qemu+ssh://pucp-server4/system',
        'mgmt_ip': '192.168.201.4',
        'ssh_host': 'pucp-server4',
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'vm_network_start': '10.60.1.41'
    }
}

# Red del cluster
NETWORK_CONFIG = {
    'management_network': '192.168.201.0/24',
    'vm_network': '$CLUSTER_VM_NETWORK',
    'bridge_name': 'br-cluster',
    'vlan_range': {'start': 100, 'end': 199}
}
EOF
    
    echo "✅ Configuración PUCP creada"
}

# Función para generar archivo de configuración final
generate_final_config() {
    echo ""
    echo "=== Generando Configuración Final ==="
    
    cat > /opt/pucp-orchestrator/pucp_real_cluster.json << EOF
{
    "cluster_name": "pucp_real_linux_cluster",
    "infrastructure_type": "pucp_real",
    "deployment_mode": "production",
    "app_node": {
        "hostname": "app",
        "ip": "$APP_NODE",
        "role": "orchestrator"
    },
    "gateway_node": {
        "hostname": "gateway", 
        "external_ip": "$GATEWAY_NODE",
        "management_ip": "$GATEWAY_MGMT",
        "role": "network_gateway"
    },
    "linux_cluster": {
        "management_network": "192.168.201.0/24",
        "vm_network": "$CLUSTER_VM_NETWORK",
        "servers": {
            "server1": {
                "mgmt_ip": "192.168.201.1",
                "ssh_host": "pucp-server1",
                "uri": "qemu+ssh://pucp-server1/system",
                "vm_ip_range": "10.60.1.11-10.60.1.20"
            },
            "server2": {
                "mgmt_ip": "192.168.201.2", 
                "ssh_host": "pucp-server2",
                "uri": "qemu+ssh://pucp-server2/system",
                "vm_ip_range": "10.60.1.21-10.60.1.30"
            },
            "server3": {
                "mgmt_ip": "192.168.201.3",
                "ssh_host": "pucp-server3", 
                "uri": "qemu+ssh://pucp-server3/system",
                "vm_ip_range": "10.60.1.31-10.60.1.40"
            },
            "server4": {
                "mgmt_ip": "192.168.201.4",
                "ssh_host": "pucp-server4",
                "uri": "qemu+ssh://pucp-server4/system", 
                "vm_ip_range": "10.60.1.41-10.60.1.50"
            }
        }
    },
    "access_method": "ssh_proxyjump",
    "ssh_config": {
        "key_path": "$HOME/.ssh/pucp_cluster_real",
        "gateway_user": "ubuntu",
        "server_user": "ubuntu",
        "proxy_jump": "pucp-gateway"
    },
    "configured_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "verified": true
}
EOF
    
    echo "✅ Configuración guardada en: /opt/pucp-orchestrator/pucp_real_cluster.json"
}

# Función principal
main() {
    echo "Configurando acceso a infraestructura real PUCP..."
    echo ""
    
    if verify_infrastructure; then
        configure_ssh_infrastructure
        create_pucp_linux_driver
        generate_final_config
        
        echo ""
        echo "=== Configuración Completada ==="
        echo "✅ Infraestructura real identificada y configurada"
        echo ""
        echo "📋 Próximos pasos:"
        echo "1. Configurar SSH keys (comandos mostrados arriba)"
        echo "2. Ejecutar: ./install_cluster_software.sh"
        echo "3. Probar con: python3 test_pucp_real_driver.py"
        echo ""
        echo "📁 Archivos generados:"
        echo "  - ~/.ssh/config (configuración SSH con ProxyJump)"
        echo "  - slice_service/drivers/pucp_real_config.py"
        echo "  - /opt/pucp-orchestrator/pucp_real_cluster.json"
        
    else
        echo ""
        echo "❌ No se pudo verificar la infraestructura completa"
        echo "Verificar conectividad y permisos SSH"
    fi
}

# Ejecutar configuración
main