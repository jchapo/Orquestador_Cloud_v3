#!/bin/bash
# analyze_ssh_differences.sh - Comparar configuración SSH entre nodos

echo "🔍 Análisis SSH: Linux Cluster vs OpenStack Cluster"
echo "=================================================="

analyze_node() {
    local node=$1
    local node_type=$2
    
    echo ""
    echo "📊 Analizando $node ($node_type)"
    echo "----------------------------------------"
    
    if ssh -o PasswordAuthentication=no -o ConnectTimeout=5 ubuntu@$node "echo 'Connected'" 2>/dev/null; then
        echo "🔐 Estado SSH: ✅ SIN contraseña"
        
        # Analizar configuración detallada
        ssh ubuntu@$node << 'EOF'
echo "📁 Directorio .ssh:"
ls -la ~/.ssh/

echo ""
echo "🔑 Contenido authorized_keys:"
if [ -f ~/.ssh/authorized_keys ]; then
    echo "   Existe: SÍ"
    echo "   Permisos: $(ls -l ~/.ssh/authorized_keys | awk '{print $1, $3, $4}')"
    echo "   Número de claves: $(wc -l < ~/.ssh/authorized_keys)"
    echo "   Tipo de claves:"
    while read -r line; do
        echo "      $(echo "$line" | awk '{print $1, $NF}')"
    done < ~/.ssh/authorized_keys
else
    echo "   Existe: NO"
fi

echo ""
echo "🔧 Configuración SSH servidor:"
sudo grep -E "^(PubkeyAuthentication|PasswordAuthentication|AuthorizedKeysFile)" /etc/ssh/sshd_config 2>/dev/null || echo "   (Sin configuración específica)"

echo ""
echo "📜 Configuración SSH completa relevante:"
sudo grep -E "(PubkeyAuthentication|PasswordAuthentication|AuthorizedKeysFile)" /etc/ssh/sshd_config | grep -v "^#"

echo ""
echo "🌐 Información de red:"
echo "   Hostname: $(hostname)"
echo "   IP principal: $(hostname -I | awk '{print $1}')"
echo "   Usuario actual: $(whoami)"

echo ""
echo "📊 Información del sistema:"
echo "   Distribución: $(lsb_release -d | cut -f2)"
echo "   Kernel: $(uname -r)"
echo "   Uptime: $(uptime | cut -d',' -f1)"
EOF
        
    else
        echo "🔐 Estado SSH: ❌ Requiere contraseña"
        echo "   No se puede analizar sin acceso automático"
    fi
}

echo "🚀 Iniciando análisis comparativo..."

# Analizar nodos que funcionan (Linux cluster)
echo ""
echo "═══════════════════════════════════════"
echo "   NODOS QUE FUNCIONAN (Linux Cluster)"
echo "═══════════════════════════════════════"

analyze_node "pucp-server1" "Linux Cluster"
analyze_node "pucp-server2" "Linux Cluster"

# Analizar nodos que no funcionan (OpenStack cluster)  
echo ""
echo "════════════════════════════════════════════"
echo "   NODOS QUE NO FUNCIONAN (OpenStack Cluster)"
echo "════════════════════════════════════════════"

echo ""
echo "⚠️  Para analizar los nodos OpenStack, necesitamos conectar manualmente:"
echo ""

for node in pucp-headnode pucp-worker1; do
    echo "📋 Para analizar $node, ejecuta:"
    echo "   ssh ubuntu@$node"
    echo "   ls -la ~/.ssh/"
    echo "   cat ~/.ssh/authorized_keys"
    echo "   sudo grep -E '(PubkeyAuthentication|PasswordAuthentication)' /etc/ssh/sshd_config"
    echo "   exit"
    echo ""
done