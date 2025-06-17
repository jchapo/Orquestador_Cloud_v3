#!/bin/bash
# setup_openstack_ssh.sh - Configurar SSH solo para nodos OpenStack

echo "🔑 Configurando SSH para nodos OpenStack"
echo "========================================"

# Nodos OpenStack que necesitan configuración
OPENSTACK_NODES=(
    "pucp-headnode:192.168.202.1"
    "pucp-worker1:192.168.202.2" 
    "pucp-worker2:192.168.202.3"
    "pucp-worker3:192.168.202.4"
)

# Verificar que tienes clave SSH
if [ ! -f ~/.ssh/id_rsa.pub ]; then
    echo "🔐 Generando clave SSH..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C "pucp-orchestrator@app"
fi

echo "📋 Tu clave pública:"
echo "$(cat ~/.ssh/id_rsa.pub)"
echo ""

# Configurar cada nodo OpenStack
for node_info in "${OPENSTACK_NODES[@]}"; do
    node_name=$(echo $node_info | cut -d: -f1)
    node_ip=$(echo $node_info | cut -d: -f2)
    
    echo "🔧 Configurando $node_name ($node_ip)..."
    echo ""
    echo "Ejecuta estos comandos:"
    echo "1. ssh ubuntu@$node_name"
    echo "2. mkdir -p ~/.ssh && chmod 700 ~/.ssh"
    echo "3. echo '$(cat ~/.ssh/id_rsa.pub)' >> ~/.ssh/authorized_keys"
    echo "4. chmod 600 ~/.ssh/authorized_keys"
    echo "5. exit"
    echo ""
    
    read -p "Presiona Enter cuando hayas configurado $node_name..."
    
    # Probar conexión
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no ubuntu@$node_name "echo 'SSH OK'" 2>/dev/null; then
        echo "✅ SSH configurado correctamente para $node_name"
    else
        echo "❌ SSH aún requiere configuración en $node_name"
    fi
    echo ""
done

echo "🧪 Probando todas las conexiones OpenStack..."
for node_info in "${OPENSTACK_NODES[@]}"; do
    node_name=$(echo $node_info | cut -d: -f1)
    
    if ssh -o ConnectTimeout=5 ubuntu@$node_name "hostname" 2>/dev/null; then
        echo "✅ $node_name: SSH OK"
    else
        echo "❌ $node_name: SSH falló"
    fi
done