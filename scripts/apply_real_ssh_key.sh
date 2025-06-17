#!/bin/bash
# apply_real_ssh_key.sh - Aplicar la clave SSH real

echo "🔧 Aplicando clave SSH real a nodos OpenStack"
echo "============================================="

# Obtener la clave real que funciona
REAL_KEY=$(ssh ubuntu@pucp-server1 "cat ~/.ssh/authorized_keys")

echo "🔑 Clave SSH real extraída:"
echo "$REAL_KEY"
echo ""

# Nodos OpenStack
OPENSTACK_NODES=("pucp-headnode" "pucp-worker1" "pucp-worker2" "pucp-worker3")

apply_real_key() {
    local node=$1
    echo "🔧 Aplicando clave real a $node..."
    
    # Conectar y aplicar la clave real
    ssh ubuntu@$node << EOF
# Limpiar y aplicar la clave real
rm -f ~/.ssh/authorized_keys
mkdir -p ~/.ssh
echo '$REAL_KEY' > ~/.ssh/authorized_keys

# Configurar permisos
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

echo "✅ Clave real aplicada en \$(hostname)"
EOF

    # Probar conexión sin contraseña
    if ssh -o PasswordAuthentication=no -o ConnectTimeout=5 ubuntu@$node "echo 'SSH sin contraseña OK en $(hostname)'" 2>/dev/null; then
        echo "✅ $node: SSH sin contraseña funciona con clave real"
    else
        echo "❌ $node: SSH aún requiere contraseña"
    fi
    echo ""
}

# Aplicar a cada nodo OpenStack
for node in "${OPENSTACK_NODES[@]}"; do
    apply_real_key $node
done

echo "🎯 Verificación final con clave real:"
for node in "${OPENSTACK_NODES[@]}"; do
    if ssh -o PasswordAuthentication=no -o ConnectTimeout=5 ubuntu@$node "hostname" 2>/dev/null; then
        echo "✅ $node: SSH configurado correctamente"
    else
        echo "❌ $node: Requiere configuración manual"
    fi
done