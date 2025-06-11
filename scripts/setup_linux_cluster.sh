#!/bin/bash
"""
PUCP Cloud Orchestrator - Linux Cluster Setup
Configura el cluster Linux para KVM/libvirt
"""

set -e

echo "=== PUCP Cloud Orchestrator - Linux Cluster Setup ==="

# Configuración
SERVERS=("server1:10.60.1.11" "server2:10.60.1.12" "server3:10.60.1.13" "server4:10.60.1.14")
GATEWAY_IP="10.60.1.1"
ORCHESTRATOR_KEY="/opt/pucp-orchestrator/keys/orchestrator_rsa"

# Función para logging
log_info() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

log_warn() {
    echo "[WARN] $1" >&2
}

# Verificar si estamos ejecutando como root
if [ "$EUID" -ne 0 ]; then
    log_error "Este script debe ejecutarse como root"
    exit 1
fi

# Crear directorio para claves SSH si no existe
mkdir -p /opt/pucp-orchestrator/keys
mkdir -p ~/.ssh

# Generar clave SSH para el orchestrator si no existe
if [ ! -f "$ORCHESTRATOR_KEY" ]; then
    log_info "Generando clave SSH para el orchestrator..."
    ssh-keygen -t rsa -b 4096 -f "$ORCHESTRATOR_KEY" -N "" -C "pucp-orchestrator@$(hostname)"
    chmod 600 "$ORCHESTRATOR_KEY"
    chmod 644 "${ORCHESTRATOR_KEY}.pub"
fi

# Función para verificar conectividad SSH
test_ssh_connectivity() {
    local server_ip=$1
    log_info "  Verificando conectividad SSH con $server_ip..."
    
    # Intentar conexión SSH con timeout
    if timeout 10 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes root@$server_ip "echo 'SSH OK'" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Función para configurar SSH automáticamente
setup_ssh_access() {
    local server_ip=$1
    local server_name=$2
    
    log_info "  Configurando acceso SSH a $server_name ($server_ip)..."
    
    # Primero verificar si ya tenemos acceso
    if test_ssh_connectivity $server_ip; then
        log_info "  ✓ SSH ya configurado para $server_name"
        return 0
    fi
    
    # Configurar SSH sin password prompt
    log_info "  Copiando clave SSH (se requerirá password)..."
    
    # Usar sshpass si está disponible, sino solicitar password manualmente
    if command -v sshpass >/dev/null 2>&1; then
        log_warn "  Usar sshpass o configurar SSH keys manualmente"
        log_warn "  Ejemplo: ssh-copy-id -i ${ORCHESTRATOR_KEY}.pub root@$server_ip"
        return 1
    else
        # Intentar ssh-copy-id con configuración especial
        SSH_COPY_ID_OPTIONS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        
        if ssh-copy-id -i "${ORCHESTRATOR_KEY}.pub" $SSH_COPY_ID_OPTIONS root@$server_ip; then
            log_info "  ✓ Clave SSH copiada a $server_name"
            return 0
        else
            log_error "  ✗ Falló la copia de clave SSH a $server_name"
            log_warn "  Configurar manualmente: ssh-copy-id -i ${ORCHESTRATOR_KEY}.pub root@$server_ip"
            return 1
        fi
    fi
}

# Función mejorada para configurar un servidor
setup_server() {
    local server_info=$1
    local server_name=$(echo $server_info | cut -d: -f1)
    local server_ip=$(echo $server_info | cut -d: -f2)
    
    log_info "Configurando $server_name ($server_ip)..."
    
    # Verificar conectividad básica
    if ! ping -c 1 -W 5 $server_ip >/dev/null 2>&1; then
        log_error "  No hay conectividad de red con $server_ip"
        return 1
    fi
    
    # Configurar SSH
    if ! setup_ssh_access $server_ip $server_name; then
        log_error "  No se pudo configurar SSH para $server_name"
        return 1
    fi
    
    # Verificar acceso SSH antes de continuar
    if ! test_ssh_connectivity $server_ip; then
        log_error "  SSH no funciona después de configuración"
        return 1
    fi
    
    # Configurar el servidor remotamente
    log_info "  Instalando paquetes en $server_name..."
    
    ssh -i "$ORCHESTRATOR_KEY" -o StrictHostKeyChecking=no root@$server_ip << 'EOF'
        set -e
        
        echo "Actualizando sistema..."
        export DEBIAN_FRONTEND=noninteractive
        apt update -q
        
        echo "Instalando paquetes KVM/libvirt..."
        apt install -y -q \
            qemu-kvm \
            libvirt-daemon-system \
            libvirt-clients \
            bridge-utils \
            virt-manager \
            qemu-utils \
            openvswitch-switch \
            python3-libvirt \
            socat \
            netcat-openbsd \
            ufw
        
        echo "Habilitando servicios..."
        systemctl enable libvirtd
        systemctl enable openvswitch-switch
        systemctl start libvirtd
        systemctl start openvswitch-switch
        
        echo "Configurando libvirt para acceso remoto..."
        # Backup de configuración original
        cp /etc/libvirt/libvirtd.conf /etc/libvirt/libvirtd.conf.backup
        
        # Configurar libvirt para acceso SSH (más seguro que TCP)
        sed -i 's/#unix_sock_group = "libvirt"/unix_sock_group = "libvirt"/' /etc/libvirt/libvirtd.conf
        sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/' /etc/libvirt/libvirtd.conf
        
        # Agregar usuario root al grupo libvirt
        usermod -a -G libvirt root
        
        echo "Configurando Open vSwitch..."
        # Crear bridge principal solo si no existe
        ovs-vsctl --may-exist add-br ovs1
        
        # Configurar VLAN trunk
        ovs-vsctl set port ovs1 trunk=100,101,102,103,104,105,106,107,108,109,110
        
        echo "Configurando storage pools..."
        # Crear directorios para libvirt
        mkdir -p /var/lib/libvirt/images
        mkdir -p /var/lib/libvirt/iso
        
        # Verificar si pool ya existe antes de crearlo
        if ! virsh pool-info default >/dev/null 2>&1; then
            virsh pool-define-as default dir - - - - "/var/lib/libvirt/images"
            virsh pool-build default
            virsh pool-start default
            virsh pool-autostart default
        fi
        
        if ! virsh pool-info iso >/dev/null 2>&1; then
            virsh pool-define-as iso dir - - - - "/var/lib/libvirt/iso"
            virsh pool-build iso
            virsh pool-start iso
            virsh pool-autostart iso
        fi
        
        echo "Configurando firewall..."
        # Habilitar UFW si no está activo
        ufw --force enable
        
        # Permitir tráfico desde la red del cluster
        ufw allow from 10.60.1.0/24 to any port 22     # SSH
        ufw allow from 10.60.1.0/24 to any port 16509  # libvirt
        ufw allow from 10.60.1.0/24 to any port 5900:6000  # VNC range
        
        echo "Reiniciando servicios..."
        systemctl restart libvirtd
        systemctl restart openvswitch-switch
        
        echo "Verificando servicios..."
        if systemctl is-active --quiet libvirtd; then
            echo "✓ libvirtd activo"
        else
            echo "✗ libvirtd no está activo"
            systemctl status libvirtd
        fi
        
        if systemctl is-active --quiet openvswitch-switch; then
            echo "✓ openvswitch activo"
        else
            echo "✗ openvswitch no está activo"
            systemctl status openvswitch-switch
        fi
        
        echo "Configuración completada en $(hostname)"
EOF
    
    local ssh_exit_code=$?
    
    if [ $ssh_exit_code -eq 0 ]; then
        log_info "  ✓ $server_name configurado exitosamente"
        return 0
    else
        log_error "  ✗ Falló la configuración de $server_name (exit code: $ssh_exit_code)"
        return 1
    fi
}

# Función para descargar imágenes (version optimizada)
download_base_images() {
    local server_info=$1
    local server_name=$(echo $server_info | cut -d: -f1)
    local server_ip=$(echo $server_info | cut -d: -f2)
    
    log_info "Descargando imágenes en $server_name..."
    
    ssh -i "$ORCHESTRATOR_KEY" -o StrictHostKeyChecking=no root@$server_ip << 'EOF'
        cd /var/lib/libvirt/images
        
        # Función para descargar imagen si no existe
        download_image() {
            local filename=$1
            local url=$2
            
            if [ ! -f "$filename" ]; then
                echo "Descargando $filename..."
                wget -q --show-progress -O "$filename" "$url"
                if [ $? -eq 0 ]; then
                    echo "✓ $filename descargado"
                else
                    echo "✗ Error descargando $filename"
                    rm -f "$filename"
                    return 1
                fi
            else
                echo "✓ $filename ya existe"
            fi
            return 0
        }
        
        # Ubuntu 20.04 Server (imagen pequeña para tests)
        download_image "ubuntu-20.04-server.qcow2" \
            "https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img"
        
        # Configurar permisos
        chown libvirt-qemu:libvirt-qemu *.qcow2 2>/dev/null || true
        chmod 644 *.qcow2 2>/dev/null || true
        
        echo "Imágenes configuradas en $(hostname)"
EOF
}

# Función para verificar configuración de un servidor
verify_server_config() {
    local server_info=$1
    local server_name=$(echo $server_info | cut -d: -f1)
    local server_ip=$(echo $server_info | cut -d: -f2)
    
    log_info "Verificando configuración de $server_name..."
    
    # Test de libvirt
    if ssh -i "$ORCHESTRATOR_KEY" -o ConnectTimeout=10 root@$server_ip "virsh list >/dev/null 2>&1"; then
        log_info "  ✓ libvirt funcional"
    else
        log_error "  ✗ libvirt no responde"
        return 1
    fi
    
    # Test de OVS
    if ssh -i "$ORCHESTRATOR_KEY" -o ConnectTimeout=10 root@$server_ip "ovs-vsctl show >/dev/null 2>&1"; then
        log_info "  ✓ Open vSwitch funcional"
    else
        log_error "  ✗ Open vSwitch no responde"
        return 1
    fi
    
    return 0
}

# Script principal
main() {
    echo ""
    log_info "Iniciando configuración de servidores del cluster..."
    
    # Configurar cada servidor
    failed_servers=()
    successful_servers=()
    
    for server in "${SERVERS[@]}"; do
        server_name=$(echo $server | cut -d: -f1)
        
        if setup_server "$server"; then
            successful_servers+=("$server")
        else
            failed_servers+=("$server")
            log_error "Falló configuración de $server_name - continuando con otros..."
        fi
        
        echo "" # Separador entre servidores
    done
    
    # Resumen de configuración
    echo ""
    echo "=== Resumen de Configuración ==="
    echo "Servidores exitosos: ${#successful_servers[@]}"
    echo "Servidores fallidos: ${#failed_servers[@]}"
    
    if [ ${#failed_servers[@]} -gt 0 ]; then
        echo "Servidores con problemas:"
        for server in "${failed_servers[@]}"; do
            echo "  - $server"
        done
        echo ""
        echo "Para configurar manualmente un servidor:"
        echo "1. ssh-copy-id -i ${ORCHESTRATOR_KEY}.pub root@<IP>"
        echo "2. Ejecutar nuevamente este script"
    fi
    
    # Si hay al menos un servidor exitoso, continuar con imágenes
    if [ ${#successful_servers[@]} -gt 0 ]; then
        echo ""
        log_info "Descargando imágenes base en servidores configurados..."
        
        # Descargar imágenes solo en servidores exitosos
        for server in "${successful_servers[@]}"; do
            download_base_images "$server" &
        done
        
        # Esperar a que terminen las descargas
        wait
        
        echo ""
        log_info "Verificando configuración final..."
        
        # Verificar servidores
        for server in "${successful_servers[@]}"; do
            verify_server_config "$server"
        done
    fi
    
    # Crear configuración del orchestrator
    create_orchestrator_config
    
    # Resumen final
    echo ""
    echo "=== Resumen Final ==="
    echo "Cluster: PUCP Linux Cluster"
    echo "Servidores configurados: ${#successful_servers[@]}/${#SERVERS[@]}"
    echo "Red del cluster: 10.60.1.0/24"
    echo "Bridge OVS: ovs1"
    echo "Configuración guardada en: /opt/pucp-orchestrator/linux_cluster_config.json"
    
    if [ ${#successful_servers[@]} -eq ${#SERVERS[@]} ]; then
        echo ""
        echo "✅ ¡Cluster Linux configurado exitosamente!"
        echo ""
        echo "Próximos pasos:"
        echo "1. Reiniciar slice_service para cargar el driver"
        echo "2. Probar con: python3 scripts/test_linux_driver.py"
        echo ""
        echo "Para probar manualmente:"
        echo "  virsh -c qemu+ssh://root@10.60.1.11/system list"
    else
        echo ""
        echo "⚠️  Configuración completada con advertencias"
        echo "   ${#failed_servers[@]} servidor(es) requieren configuración manual"
    fi
}

# Función para crear configuración del orchestrator
create_orchestrator_config() {
    log_info "Creando configuración del orchestrator..."
    
    cat > /opt/pucp-orchestrator/linux_cluster_config.json << EOF
{
    "cluster_name": "pucp_linux_cluster",
    "infrastructure_type": "linux",
    "hypervisors": {
        "server1": {
            "uri": "qemu+ssh://root@10.60.1.11/system",
            "ip": "10.60.1.11",
            "port": 5811,
            "max_vcpus": 8,
            "max_ram": 16384,
            "max_disk": 100
        },
        "server2": {
            "uri": "qemu+ssh://root@10.60.1.12/system", 
            "ip": "10.60.1.12",
            "port": 5812,
            "max_vcpus": 8,
            "max_ram": 16384,
            "max_disk": 100
        },
        "server3": {
            "uri": "qemu+ssh://root@10.60.1.13/system",
            "ip": "10.60.1.13", 
            "port": 5813,
            "max_vcpus": 8,
            "max_ram": 16384,
            "max_disk": 100
        },
        "server4": {
            "uri": "qemu+ssh://root@10.60.1.14/system",
            "ip": "10.60.1.14",
            "port": 5814,
            "max_vcpus": 8,
            "max_ram": 16384,
            "max_disk": 100
        }
    },
    "network_config": {
        "ovs_bridge": "ovs1",
        "network_range": "10.60.1.0/24",
        "gateway_ip": "10.60.1.1",
        "vlan_range": {
            "start": 100,
            "end": 199
        }
    },
    "ssh_config": {
        "key_path": "/opt/pucp-orchestrator/keys/orchestrator_rsa",
        "user": "root"
    },
    "setup_completed": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

# Ejecutar script principal
main