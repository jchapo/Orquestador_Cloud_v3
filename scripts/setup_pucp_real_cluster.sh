#!/bin/bash
"""
Configurar conexión con el cluster real de PUCP
"""

set -e

echo "=== Configuración para Cluster Real PUCP ==="

# Cargar configuración verificada
CONFIG_FILE="/opt/pucp-orchestrador/pucp_real_infrastructure.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Ejecutar primero ./verify_pucp_infrastructure.sh"
    exit 1
fi

echo "Cargando configuración verificada..."
ACCESS_METHOD=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['access_method'])")
GATEWAY_IP=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['gateway']['ip'])")

echo "Método de acceso: $ACCESS_METHOD"
echo "Gateway: $GATEWAY_IP"
echo ""

# Configurar SSH para acceso
configure_ssh_access() {
    echo "=== Configurando Acceso SSH ==="
    
    # Crear directorio SSH si no existe
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    
    # Generar clave para PUCP si no existe
    PUCP_KEY="$HOME/.ssh/pucp_cluster_rsa"
    if [ ! -f "$PUCP_KEY" ]; then
        echo "Generando clave SSH para cluster PUCP..."
        ssh-keygen -t rsa -b 4096 -f "$PUCP_KEY" -N "" -C "pucp-cluster@$(hostname)"
        chmod 600 "$PUCP_KEY"
    fi
    
    echo "Clave SSH: $PUCP_KEY"
    echo "Clave pública:"
    cat "${PUCP_KEY}.pub"
    echo ""
    
    # Configurar SSH config
    echo "Configurando SSH config..."
    
    if [ "$ACCESS_METHOD" = "direct" ]; then
        # Acceso directo a servidores
        cat >> ~/.ssh/config << EOF

# PUCP Cluster - Acceso Directo
Host pucp-server1
    HostName 10.60.1.11
    User root
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server2
    HostName 10.60.1.12
    User root
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server3
    HostName 10.60.1.13
    User root
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server4
    HostName 10.60.1.14
    User root
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF

    else
        # Acceso vía gateway con ProxyJump
        cat >> ~/.ssh/config << EOF

# PUCP Cluster - Acceso vía Gateway
Host pucp-gateway
    HostName $GATEWAY_IP
    User root
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server1
    HostName 10.60.1.11
    User root
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server2
    HostName 10.60.1.12
    User root
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server3
    HostName 10.60.1.13
    User root
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host pucp-server4
    HostName 10.60.1.14
    User root
    ProxyJump pucp-gateway
    IdentityFile $PUCP_KEY
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
    fi
    
    echo "✅ SSH configurado"
}

# Actualizar Linux Driver para infraestructura real
update_linux_driver() {
    echo ""
    echo "=== Actualizando Linux Driver ==="
    
    # Backup del driver actual
    cp slice_service/drivers/linux_driver.py slice_service/drivers/linux_driver_backup.py
    
    # Crear configuración específica para PUCP
    cat > slice_service/drivers/pucp_config.py << EOF
#!/usr/bin/env python3
"""
Configuración específica para infraestructura real PUCP
"""

# Configuración de hypervisors para PUCP real
PUCP_HYPERVISORS = {
    'server1': {
        'uri': 'qemu+ssh://pucp-server1/system',
        'ip': '10.60.1.11',
        'port': 5811,
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'ssh_host': 'pucp-server1'
    },
    'server2': {
        'uri': 'qemu+ssh://pucp-server2/system',
        'ip': '10.60.1.12',
        'port': 5812,
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'ssh_host': 'pucp-server2'
    },
    'server3': {
        'uri': 'qemu+ssh://pucp-server3/system',
        'ip': '10.60.1.13',
        'port': 5813,
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'ssh_host': 'pucp-server3'
    },
    'server4': {
        'uri': 'qemu+ssh://pucp-server4/system',
        'ip': '10.60.1.14',
        'port': 5814,
        'max_vcpus': 8,
        'max_ram': 16384,
        'max_disk': 100,
        'ssh_host': 'pucp-server4'
    }
}

# Configuración de red PUCP
PUCP_NETWORK_CONFIG = {
    'ovs_bridge': 'ovs1',
    'network_range': '10.60.1.0/24',
    'gateway_ip': '$GATEWAY_IP',
    'management_network': '192.168.201.0/24'
}

# Acceso method
ACCESS_METHOD = '$ACCESS_METHOD'
GATEWAY_IP = '$GATEWAY_IP'
EOF
    
    echo "✅ Configuración PUCP creada"
}

# Test de conectividad
test_connectivity() {
    echo ""
    echo "=== Probando Conectividad ==="
    
    servers=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")
    
    for server in "${servers[@]}"; do
        echo "Probando $server..."
        
        if timeout 10 ssh -o ConnectTimeout=5 "$server" "echo 'SSH OK'; hostname" 2>/dev/null; then
            echo "  ✅ SSH OK"
        else
            echo "  ❌ SSH falló"
            echo "  Asegúrate de haber copiado la clave pública:"
            echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub $server"
        fi
    done
}

# Función principal
main() {
    echo "Configurando acceso al cluster real PUCP..."
    echo ""
    
    configure_ssh_access
    update_linux_driver
    
    echo ""
    echo "=== Configuración SSH Manual Requerida ==="
    echo "Para completar la configuración, debes copiar tu clave pública a cada servidor:"
    echo ""
    
    if [ "$ACCESS_METHOD" = "direct" ]; then
        echo "Comandos para ejecutar:"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub root@10.60.1.11"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub root@10.60.1.12"  
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub root@10.60.1.13"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub root@10.60.1.14"
    else
        echo "Primero configurar gateway, luego servidores:"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub root@$GATEWAY_IP"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub pucp-server1"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub pucp-server2"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub pucp-server3"
        echo "  ssh-copy-id -i ~/.ssh/pucp_cluster_rsa.pub pucp-server4"
    fi
    
    echo ""
    echo "Después de configurar SSH, ejecutar:"
    echo "  ./test_pucp_connectivity.sh"
    
    test_connectivity
}

# Ejecutar configuración
main