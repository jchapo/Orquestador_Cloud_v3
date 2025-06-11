#!/bin/bash
# scripts/verify_cluster_setup.sh

echo "=== Verificando Configuración del Cluster ==="

SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")
configured_servers=()
failed_servers=()

for server in "${SERVERS[@]}"; do
    echo ""
    echo "🔍 Verificando $server..."
    
    # Test básico de conectividad
    if ! ssh -o ConnectTimeout=5 "$server" "echo 'Connected'" >/dev/null 2>&1; then
        echo "  ❌ SSH connection failed"
        failed_servers+=("$server")
        continue
    fi
    
    # Verificar grupos
    groups=$(ssh "$server" "groups")
    echo "  Grupos: $groups"
    
    # Test libvirt
    echo "  Testing libvirt..."
    if ssh "$server" "virsh list >/dev/null 2>&1"; then
        echo "    ✅ virsh works"
        libvirt_ok=true
    else
        echo "    ❌ virsh failed"
        echo "    Error:"
        ssh "$server" "virsh list 2>&1 | head -2 | sed 's/^/      /'"
        libvirt_ok=false
    fi
    
    # Test OVS
    echo "  Testing OVS..."
    if ssh "$server" "sudo ovs-vsctl show >/dev/null 2>&1"; then
        echo "    ✅ OVS works"
        ovs_ok=true
    else
        echo "    ❌ OVS failed"
        ovs_ok=false
    fi
    
    # Test storage pool
    echo "  Testing storage pool..."
    if ssh "$server" "virsh pool-list --all | grep -q default"; then
        echo "    ✅ Storage pool exists"
        pool_ok=true
    else
        echo "    ❌ Storage pool missing"
        pool_ok=false
    fi
    
    # Resumen del servidor
    if $libvirt_ok && $ovs_ok && $pool_ok; then
        echo "  ✅ $server completamente configurado"
        configured_servers+=("$server")
    else
        echo "  ⚠️  $server parcialmente configurado"
        failed_servers+=("$server")
    fi
done

echo ""
echo "═══════════════════════════════════════"
echo "📊 RESUMEN FINAL"
echo "═══════════════════════════════════════"
echo "Servidores correctamente configurados: ${#configured_servers[@]}/4"
echo "Servidores con problemas: ${#failed_servers[@]}/4"
echo ""

if [ ${#configured_servers[@]} -gt 0 ]; then
    echo "✅ Servidores funcionando:"
    for server in "${configured_servers[@]}"; do
        echo "   - $server"
    done
fi

if [ ${#failed_servers[@]} -gt 0 ]; then
    echo "❌ Servidores con problemas:"
    for server in "${failed_servers[@]}"; do
        echo "   - $server"
    done
fi

echo ""
if [ ${#configured_servers[@]} -ge 1 ]; then
    echo "🚀 Puedes proceder con el testing del driver:"
    echo "   python3 scripts/test_pucp_real_driver.py"
else
    echo "⚠️  Necesitas al menos 1 servidor configurado para continuar"
fi