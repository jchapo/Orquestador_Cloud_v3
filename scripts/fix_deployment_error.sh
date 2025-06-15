#!/bin/bash
# fix_deployment_error.sh

echo "🔧 Solucionando error de deployment de hostname"

cd /opt/pucp-orchestrador/slice_service/drivers

# Hacer backup
cp linux_driver.py linux_driver.py.backup_$(date +%s)

# Agregar logging adicional al método deploy_slice
sed -i '/def deploy_slice(self, slice_config: Dict, placement: Dict) -> Dict:/a \
        """Despliega un slice completo con sus VMs y redes"""\
        deployed_vms = []\
        created_networks = []\
        errors = []\
        \
        slice_id = slice_config.get("id", str(uuid.uuid4()))\
        \
        try:\
            # DEBUG: Logging para debug\
            logger.info(f"Placement result: {placement}")\
            logger.info(f"Slice config for driver: {slice_config}")' linux_driver.py

# Agregar verificación de hostname
sed -i '/server_assignment = placement\[vm_name\]/a \
            logger.info(f"Server assignment for {vm_name}: {server_assignment}")\
            \
            # Verificar que tenemos la clave hostname\
            if "hostname" not in server_assignment:\
                error_msg = f"No hostname found in placement for VM {vm_name}: {server_assignment}"\
                logger.error(error_msg)\
                errors.append(error_msg)\
                continue' linux_driver.py

# Agregar logging antes de crear VM
sed -i '/server_name = server_assignment\["hostname"\]/a \
            logger.info(f"Creating VM {vm_name} on server {server_name}")' linux_driver.py

# Agregar logging de excepciones
sed -i '/error_msg = f"Failed to deploy VM {vm_name}: {e}"/a \
                logger.error(f"Exception type: {type(e)}")\
                logger.error(f"Exception args: {e.args}")' linux_driver.py

echo "✅ Corrección aplicada"

# Reiniciar slice service
echo "🔄 Reiniciando slice service..."
sudo systemctl restart pucp-slice-service

# Esperar a que esté listo
sleep 5

echo "🧪 Probando deployment..."
cd /opt/pucp-orchestrator/scripts
python3 test_complete_topology.py
