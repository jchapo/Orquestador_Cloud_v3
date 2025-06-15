#!/bin/bash
# check_qemu_machine_types.sh - Verificar tipos de máquina QEMU disponibles

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVERS=("server1" "server2" "server3" "server4")
SUDO_PASSWORD="ubuntu"

echo -e "${GREEN}🔍 Verificando tipos de máquina QEMU disponibles${NC}"
echo "================================================="

for server in "${SERVERS[@]}"; do
    echo -e "\n${YELLOW}🖥️  $server${NC}"
    echo "-------------"
    
    # Verificar versión de QEMU
    echo "📦 Versión de QEMU:"
    ssh ubuntu@pucp-$server "qemu-system-x86_64 --version | head -1" | sed 's/^/   /'
    
    # Listar tipos de máquina disponibles
    echo -e "\n🖥️  Tipos de máquina disponibles:"
    ssh ubuntu@pucp-$server "qemu-system-x86_64 -machine help | grep -E '(pc-|q35)' | head -10" | sed 's/^/   /'
    
    # Mostrar el tipo por defecto
    echo -e "\n📋 Tipo por defecto:"
    ssh ubuntu@pucp-$server "qemu-system-x86_64 -machine help | head -3" | sed 's/^/   /'
done
