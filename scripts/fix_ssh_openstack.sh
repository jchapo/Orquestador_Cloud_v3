#!/bin/bash
# fix_ssh_openstack.sh - Corregir SSH para OpenStack

echo "🔧 Corrigiendo configuración SSH para OpenStack"
echo "=============================================="

# Tu clave pública
PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+S6JuvwaKFIGR2UBLpipJbWsubsKRqk3q462LSQW8T2uQ/XI0Nd57N6zADC0ww0qkGlt2xhopNtCgGgpeZ6NQ7g2tHvBhS6R08sC2w6pZCzP/0LOt5X3gUuMVIDYiBW201/LFGKIq4Nfiwaq1YRohLBmIJaBFyVT7QkTQfoMQLjexT5L5VTEUO5uD/mptBVBzqV4zkXhpj2hNNabPfhel6ChaXAOKvJ9DzXm1gQRTInhsuPTwKrQIE+eL8sO2ACWeWboRJENsNA77ACwFaQzjux4h/VyvN2AufEa5spEWI7BnX9ogLJUXou9c8ymuvTOhJmbmz4nXVBABrqjDsirb5Y5SJdC93gZApM68D7pgpIwghU57G711p171ruKpMeRU87uh498orgOL0p+mx1xIIJBWeTw/ZGi5qKr+Pxwj5SfiXts/ut/coDu+ZM6YxQB9yq0ISVCuIzDK09xFuvPBU7PkP+M0G0kW87hLz4j32vD9yeEZWLgjkFJsxR8umspN3wBfBqyJnSCpZoiOrdymk1eBLNXT+z5QrQroz+JWK0xbxRRMS8MTRFghtbHawvFrrjeyloIEPvRVDriy5LmXtKEFlTMUFSlPD4cgMPUoVgyWjggx1hf2LCUiHBbqOprJOAJ7kIZfZ6K6L6cy1GXxWt6aci1AzM6vpk2ilT5Mlw== ubuntu@app"

# Nodos OpenStack
NODES=("pucp-headnode" "pucp-worker1" "pucp-worker2" "pucp-worker3")

fix_node() {
    local node=$1
    echo ""
    echo "🔧 Corrigiendo $node..."
    
    # Conectar y corregir configuración
    ssh ubuntu@$node << EOF
# Limpiar y recrear authorized_keys
rm -f ~/.ssh/authorized_keys
mkdir -p ~/.ssh
echo '$PUBLIC_KEY' > ~/.ssh/authorized_keys

# Configurar permisos correctos
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chown ubuntu:ubuntu ~/.ssh
chown ubuntu:ubuntu ~/.ssh/authorized_keys

# Verificar configuración SSH del servidor
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config

# Reiniciar SSH
sudo systemctl restart sshd

echo "✅ Configuración corregida en \$(hostname)"
EOF

    # Probar conexión sin contraseña
    echo "🧪 Probando conexión sin contraseña..."
    if ssh -o PasswordAuthentication=no -o ConnectTimeout=5 ubuntu@$node "echo 'SSH sin contraseña OK'" 2>/dev/null; then
        echo "✅ $node: SSH sin contraseña funciona"
    else
        echo "❌ $node: SSH aún requiere contraseña"
    fi
}

# Corregir cada nodo
for node in "${NODES[@]}"; do
    fix_node $node
done

echo ""
echo "🎯 Verificación final:"
for node in "${NODES[@]}"; do
    if ssh -o PasswordAuthentication=no -o ConnectTimeout=5 ubuntu@$node "hostname" 2>/dev/null; then
        echo "✅ $node: SSH configurado correctamente"
    else
        echo "❌ $node: Requiere configuración manual"
    fi
done