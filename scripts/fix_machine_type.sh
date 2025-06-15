#!/bin/bash
# fix_machine_type.sh - Corregir tipo de máquina en LinuxDriver

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🛠️ Corrigiendo tipo de máquina en LinuxDriver${NC}"
echo "============================================="

# Hacer backup
cp slice_service/drivers/linux_driver.py slice_service/drivers/linux_driver.py.backup.$(date +%Y%m%d_%H%M%S)
echo -e "${YELLOW}📁 Backup creado${NC}"

# Mostrar lo que vamos a cambiar
echo -e "${YELLOW}🔍 Buscar línea problemática...${NC}"
grep -n "pc-q35-5.2" slice_service/drivers/linux_driver.py || echo "   No se encontró referencia directa a pc-q35-5.2"

echo -e "${YELLOW}💡 Aplicando corrección automática...${NC}"

# Usar sed para reemplazar la línea problemática
sed -i 's/machine="pc-q35-5.2"/machine='"'"'{machine_type}'"'"'/g' slice_service/drivers/linux_driver.py

echo -e "${GREEN}✅ Corrección aplicada${NC}"
echo -e "${YELLOW}📋 Recuerda agregar el método _get_compatible_machine_type manualmente${NC}"
