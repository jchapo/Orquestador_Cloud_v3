#!/bin/bash
# verify_libvirt_networks.sh - Verificar redes de libvirt

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVERS=("server1" "server2" "server3" "server4")
SUDO_PASSWORD="ubuntu"

echo -e "${GREEN}🔍 Verificando redes de libvirt${NC}"
echo "=================================="

for server in "${SERVERS[@]}"; do
    echo -e "\n${YELLOW}🖥️  $server${NC}"
    echo "-------------"
    
    # Listar redes
    echo -e "📋 Redes disponibles:"
    ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-list --all" | sed 's/^/   /'
    
    # Verificar configuración de ovs-network
    if ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-list --all | grep ovs-network" 2>/dev/null; then
        echo -e "\n📋 Configuración de ovs-network:"
        ssh ubuntu@pucp-$server "echo '$SUDO_PASSWORD' | sudo -S virsh net-dumpxml ovs-network" | sed 's/^/   /'
    else
        echo -e "${RED}❌ Red ovs-network no encontrada${NC}"
    fi
done
