#!/bin/bash
# fix_libvirt_ovs.sh - Arreglar configuración de libvirt para OVS

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVERS=("server1" "server2" "server3" "server4")
BRIDGE_NAME="ovs1"
SUDO_PASSWORD="ubuntu"

echo -e "${GREEN}🔧 Arreglando configuración de libvirt para OVS${NC}"
echo "================================================="

fix_server() {
    local server=$1
    echo -e "\n${YELLOW}🖥️  Arreglando $server${NC}"
    
    # 1. Verificar que OVS bridge existe
    if ! ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S ovs-vsctl br-exists $BRIDGE_NAME" 2>/dev/null; then
        echo -e "${RED}❌ Bridge $BRIDGE_NAME no existe en $server${NC}"
        return 1
    fi
    
    # 2. Parar red existente si está activa
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-destroy ovs-network" 2>/dev/null || true
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-undefine ovs-network" 2>/dev/null || true
    
    # 3. Crear network XML CORRECTO para OVS
    cat > /tmp/ovs-network-fixed.xml << EOF
<network>
  <name>ovs-network</name>
  <forward mode='bridge'/>
  <bridge name='$BRIDGE_NAME'/>
  <virtualport type='openvswitch'/>
</network>
EOF
    
    # 4. Copiar y configurar
    scp /tmp/ovs-network-fixed.xml ubuntu@pucp-$server:/tmp/
    
    echo -e "${YELLOW}📋 Definiendo red corregida...${NC}"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-define /tmp/ovs-network-fixed.xml"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-autostart ovs-network"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-start ovs-network"
    
    # 5. Verificar
    echo -e "${YELLOW}✅ Verificando configuración...${NC}"
    if ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-list --all | grep ovs-network | grep active" 2>/dev/null; then
        echo -e "${GREEN}✅ $server: Red OVS configurada y activa${NC}"
        
        # Mostrar configuración
        echo -e "${YELLOW}📋 Configuración de la red:${NC}"
        ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-dumpxml ovs-network" | grep -E "(bridge|virtualport)" | sed 's/^/   /'
        
    else
        echo -e "${RED}❌ $server: Error configurando red OVS${NC}"
        return 1
    fi
    
    # 6. Limpiar
    ssh ubuntu@pucp-$server "rm -f /tmp/ovs-network-fixed.xml"
    
    return 0
}

# Procesar todos los servidores
for server in "${SERVERS[@]}"; do
    fix_server $server
done

echo -e "\n${GREEN}🎉 Configuración corregida${NC}"
echo -e "${YELLOW}💡 Ahora intenta ejecutar el test de nuevo${NC}"

# Limpiar archivos temporales
rm -f /tmp/ovs-network-fixed.xml
