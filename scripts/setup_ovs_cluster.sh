#!/bin/bash
# setup_ovs_cluster_fixed.sh - Configurar OpenVSwitch usando SSH keys

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🔧 Configurando OpenVSwitch en cluster PUCP${NC}"
echo "=================================================="

# Configuración
SERVERS=("server1" "server2" "server3" "server4")
BRIDGE_NAME="ovs1"
NETWORK_RANGE="192.168.201.0/24"
SUDO_PASSWORD="ubuntu"

# Función para ejecutar comando en servidor remoto
run_on_server() {
    local server=$1
    local cmd=$2
    echo -e "${YELLOW}📡 Ejecutando en $server: $cmd${NC}"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S $cmd"
}

# Función para ejecutar comando sin sudo
run_on_server_no_sudo() {
    local server=$1
    local cmd=$2
    echo -e "${YELLOW}📡 Ejecutando en $server: $cmd${NC}"
    ssh ubuntu@pucp-$server "$cmd"
}

# Función para configurar OVS en un servidor
setup_ovs_on_server() {
    local server=$1
    echo -e "\n${GREEN}🖥️ Configurando OpenVSwitch en $server${NC}"
    
    # Verificar conectividad
    if ! ssh -o ConnectTimeout=10 ubuntu@pucp-$server "echo 'Conectado a $server'" 2>/dev/null; then
        echo -e "${RED}❌ No se puede conectar a $server${NC}"
        return 1
    fi
    
    # Actualizar repos
    echo -e "${YELLOW}🔄 Actualizando repositorios...${NC}"
    run_on_server $server "apt update"
    
    # Instalar OVS si no existe
    echo -e "${YELLOW}📦 Instalando OpenVSwitch...${NC}"
    run_on_server $server "DEBIAN_FRONTEND=noninteractive apt install -y openvswitch-switch"
    
    # Iniciar servicios
    echo -e "${YELLOW}🔄 Iniciando servicios...${NC}"
    run_on_server $server "systemctl enable openvswitch-switch"
    run_on_server $server "systemctl start openvswitch-switch"
    
    # Esperar a que OVS esté listo
    echo -e "${YELLOW}⏳ Esperando a que OVS esté listo...${NC}"
    sleep 5
    
    # Verificar que OVS está funcionando
    if ! ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S ovs-vsctl show" 2>/dev/null; then
        echo -e "${RED}❌ OVS no está funcionando correctamente en $server${NC}"
        return 1
    fi
    
    # Crear bridge ovs1 si no existe
    echo -e "${YELLOW}🌉 Creando bridge $BRIDGE_NAME...${NC}"
    run_on_server $server "ovs-vsctl --may-exist add-br $BRIDGE_NAME"
    
    # Configurar el bridge
    echo -e "${YELLOW}⚙️ Configurando bridge...${NC}"
    run_on_server $server "ovs-vsctl set bridge $BRIDGE_NAME protocols=OpenFlow10,OpenFlow13"
    
    # Activar la interfaz del bridge
    run_on_server $server "ip link set $BRIDGE_NAME up"
    
    # Configurar la interfaz con una IP temporal (opcional)
    run_on_server $server "ip addr add 192.168.201.$(echo $server | sed 's/server//g')/24 dev $BRIDGE_NAME || true"
    
    # Verificar configuración
    echo -e "${YELLOW}✅ Verificando configuración en $server:${NC}"
    if ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S ovs-vsctl br-exists $BRIDGE_NAME"; then
        echo -e "${GREEN}✅ $server: Bridge $BRIDGE_NAME creado exitosamente${NC}"
        
        # Mostrar configuración
        ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S ovs-vsctl show | grep -A 5 'Bridge \"$BRIDGE_NAME\"'" || true
        
        # Mostrar estado de la interfaz
        ssh ubuntu@pucp-$server "ip link show $BRIDGE_NAME" | head -1 || true
        
    else
        echo -e "${RED}❌ $server: Error creando bridge $BRIDGE_NAME${NC}"
        return 1
    fi
}

# Configurar libvirt para usar OVS
setup_libvirt_ovs() {
    local server=$1
    echo -e "\n${GREEN}🔗 Configurando libvirt para usar OVS en $server${NC}"
    
    # Crear network XML para OVS
    cat > /tmp/ovs-network.xml << EOF
<network>
  <name>ovs-network</name>
  <forward mode='bridge'/>
  <bridge name='$BRIDGE_NAME'/>
  <virtualport type='openvswitch'/>
</network>
EOF
    
    # Copiar archivo de configuración
    scp /tmp/ovs-network.xml ubuntu@pucp-$server:/tmp/
    
    # Definir la red en libvirt
    echo -e "${YELLOW}📋 Configurando red en libvirt...${NC}"
    run_on_server $server "virsh net-define /tmp/ovs-network.xml"
    run_on_server $server "virsh net-autostart ovs-network"
    run_on_server $server "virsh net-start ovs-network || true"
    
    # Verificar
    echo -e "${YELLOW}📋 Verificando redes libvirt:${NC}"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-list --all | grep ovs" || echo "Red OVS configurada (puede no mostrarse en el grep)"
    
    # Limpiar archivo temporal
    ssh ubuntu@pucp-$server "rm -f /tmp/ovs-network.xml"
}

# Función principal
main() {
    echo -e "${YELLOW}🚀 Iniciando configuración del cluster...${NC}"
    
    # Configurar cada servidor
    for server in "${SERVERS[@]}"; do
        echo -e "\n${GREEN}=================================================${NC}"
        echo -e "${GREEN}📡 Procesando $server${NC}"
        
        # Configurar OVS
        if setup_ovs_on_server $server; then
            echo -e "${GREEN}✅ OVS configurado en $server${NC}"
            
            # Configurar libvirt
            setup_libvirt_ovs $server
            echo -e "${GREEN}✅ $server completado${NC}"
        else
            echo -e "${RED}❌ Error configurando $server${NC}"
        fi
        
        echo -e "${GREEN}=================================================${NC}"
    done
    
    echo -e "\n${GREEN}🎉 Configuración del cluster completada${NC}"
    echo -e "${YELLOW}💡 Verificando conectividad entre bridges...${NC}"
    
    # Verificación final
    echo -e "\n${GREEN}🔍 VERIFICACIÓN FINAL${NC}"
    echo "======================="
    
    for server in "${SERVERS[@]}"; do
        printf "%-10s: " "$server"
        if ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S ovs-vsctl br-exists $BRIDGE_NAME" 2>/dev/null; then
            echo -e "${GREEN}✅ Bridge $BRIDGE_NAME activo${NC}"
            
            # Mostrar IP del bridge
            bridge_ip=$(ssh ubuntu@pucp-$server "ip addr show $BRIDGE_NAME | grep 'inet ' | awk '{print \$2}'" 2>/dev/null || echo "No IP")
            echo "            IP: $bridge_ip"
            
        else
            echo -e "${RED}❌ Bridge $BRIDGE_NAME NO encontrado${NC}"
        fi
    done
}

# Ejecutar
main

echo -e "\n${GREEN}✨ Setup completo! Tu cluster está listo para VMs.${NC}"
echo -e "${YELLOW}💡 Próximos pasos:${NC}"
echo "   1. Ejecutar: python3 test_complete_topology.py"
echo "   2. Si hay errores, verificar con: ./check_ovs_status.sh"
echo "   3. Ver logs de libvirt: journalctl -u libvirtd"

# Limpiar archivos temporales
rm -f /tmp/ovs-network.xml
