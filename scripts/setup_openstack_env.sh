#!/bin/bash

echo "Configurando el entorno OpenStack para PUCP Cloud Orchestrator"
echo "============================================================="

VERDE='\033[0;32m'
ROJO='\033[0;31m'
AMARILLO='\033[1;33m'
NC='\033[0m'

if [ ! -f "slice_service/slice_service.py" ]; then
    echo -e "${ROJO}Error: Ejecute este script desde el directorio raíz del proyecto${NC}"
    exit 1
fi

echo -e "${AMARILLO}Instalando las dependencias de OpenStack para Python...${NC}"
source venv/bin/activate
pip install -r requirements_openstack.txt

if [ $? -eq 0 ]; then
    echo -e "${VERDE}Dependencias de Python instaladas${NC}"
else
    echo -e "${ROJO}Error al instalar las dependencias de Python${NC}"
    exit 1
fi

echo -e "${AMARILLO}Probando la conectividad con OpenStack...${NC}"
python3 << EOF
import sys
sys.path.append('.')

try:
    from slice_service.openstack.config import OpenStackConfig
    from slice_service.openstack.api_client import OpenStackAPIClient
    
    config = OpenStackConfig()
    client = OpenStackAPIClient(config.get_auth_config())
    
    # Probar conexión
    token = client.session.get_token()
    print("Conexión exitosa con OpenStack Keystone")
    
    # Probar Nova
    servers = client.nova.servers.list()
    print(f"Servicio Nova accesible - Se encontraron {len(servers)} servidores existentes")
    
    # Probar Neutron
    networks = client.neutron.list_networks()['networks']
    print(f"Servicio Neutron accesible - Se encontraron {len(networks)} redes")
    
except Exception as e:
    print(f"Error al conectar con OpenStack: {e}")
    sys.exit(1)
EOF

if [ $? -ne 0 ]; then
    echo -e "${ROJO}Prueba de conexión con OpenStack fallida${NC}"
    echo "Por favor verifique:"
    echo "  1. Los servicios de OpenStack están corriendo en 10.60.2.21"
    echo "  2. Las credenciales en openstack_cluster_config.json son correctas"
    echo "  3. La conectividad de red con el clúster de OpenStack"
    exit 1
fi

echo -e "${AMARILLO}Configurando los recursos de OpenStack...${NC}"

cat > /tmp/openstack_admin.rc << EOF
export OS_AUTH_URL=http://10.60.2.21:5000/v3
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=openstack123
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_REGION_NAME=RegionOne
EOF

source /tmp/openstack_admin.rc

echo -e "${AMARILLO}Verificando los flavors...${NC}"
if ! openstack flavor show small >/dev/null 2>&1; then
    openstack flavor create --vcpus 1 --ram 512 --disk 10 small
    echo -e "${VERDE}flavor 'small' creado${NC}"
fi

if ! openstack flavor show medium >/dev/null 2>&1; then
    openstack flavor create --vcpus 2 --ram 1024 --disk 20 medium
    echo -e "${VERDE}flavor 'medium' creado${NC}"
fi

if ! openstack flavor show large >/dev/null 2>&1; then
    openstack flavor create --vcpus 2 --ram 2048 --disk 40 large
    echo -e "${VERDE}flavor 'large' creado${NC}"
fi


echo -e "${AMARILLO}Verificando las imágenes de prueba...${NC}"
if ! openstack image show cirros-0.5.2 >/dev/null 2>&1; then
    echo "Descargando la imagen de prueba Cirros..."
    wget -q http://download.cirros-cloud.net/0.5.2/cirros-0.5.2-x86_64-disk.img
    openstack image create "cirros-0.5.2" \
        --file cirros-0.5.2-x86_64-disk.img \
        --disk-format qcow2 \
        --container-format bare \
        --public
    rm -f cirros-0.5.2-x86_64-disk.img
    echo -e "${VERDE}Imagen de prueba 'cirros-0.5.2' creada${NC}"
fi

echo -e "${AMARILLO}Verificando la red de proveedor...${NC}"
if ! openstack network show provider >/dev/null 2>&1; then
    openstack network create provider \
        --provider-network-type vlan \
        --provider-physical-network physnet1 \
        --provider-segment 200 \
        --external \
        --share
    
    openstack subnet create provider-subnet \
        --network provider \
        --allocation-pool start=10.60.2.100,end=10.60.2.200 \
        --gateway 10.60.2.1 \
        --subnet-range 10.60.2.0/24 \
        --no-dhcp
    
    echo -e "${VERDE}Red de proveedor creada${NC}"
fi

rm -f /tmp/openstack_admin.rc

echo -e "${VERDE}¡Configuración del entorno OpenStack completa!${NC}"
echo ""
echo "Próximos pasos:"
echo "  1. Probar el controlador de OpenStack: python3 scripts/test_openstack_driver.py"
echo "  2. Desplegar un slice de prueba: python3 scripts/deploy_openstack_slice.py"