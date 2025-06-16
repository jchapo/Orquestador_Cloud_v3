#!/bin/bash
# setup_ssh_keys.sh - Configurar SSH keys para acceso sin contraseña

SERVERS=("server1" "server2" "server3" "server4" "headnode" "worker1" "worker2" "worker3")
SSH_USER="ubuntu"
PASSWORD="ubuntu"

echo "🔑 Configurando SSH keys para acceso sin contraseña"
echo "================================================="

# Generar SSH key si no existe
if [ ! -f ~/.ssh/id_rsa ]; then
    echo "🔧 Generando SSH key..."
    ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
fi

# Instalar sshpass si no existe
if ! command -v sshpass &> /dev/null; then
    echo "📦 Instalando sshpass..."
    sudo apt update && sudo apt install -y sshpass
fi

# Copiar keys a cada servidor
for server in "${SERVERS[@]}"; do
    echo "📡 Configurando $server..."
    
    # Copiar SSH key
    sshpass -p "$PASSWORD" ssh-copy-id -o StrictHostKeyChecking=no $SSH_USER@pucp-$server
    
    # Verificar acceso sin contraseña
    if ssh -o StrictHostKeyChecking=no $SSH_USER@pucp-$server "echo 'SSH sin contraseña funcionando'" 2>/dev/null; then
        echo "✅ $server: SSH key configurado"
    else
        echo "❌ $server: Error configurando SSH key"
    fi
done

echo "🎉 SSH keys configurados!"
