#!/bin/bash
# Script para diagnosticar y arreglar Placement API en OpenStack

echo "🔧 PUCP OpenStack - Arreglar Placement API"
echo "=" * 60

# Conectar al headnode donde está el controller
echo "🔍 1. Verificando estado de Placement API en headnode..."
ssh ubuntu@10.20.12.187 -p 5821 "ssh ubuntu@10.60.2.21 << 'HEADNODE_CHECK'
echo \"=== HEADNODE: \$(hostname) ===\"

echo \"📊 1. Verificando servicios Placement:\"
systemctl is-active placement-api && echo \"✅ placement-api: RUNNING\" || echo \"❌ placement-api: NOT RUNNING\"

echo \"\\n📡 2. Verificando puerto Placement (6868):\"
netstat -tlnp | grep :6868 || echo \"❌ Puerto 6868 no está escuchando\"

echo \"\\n🔌 3. Probando conexión a Placement API:\"
curl -s -I http://localhost:6868/ | head -1 || echo \"❌ No responde en puerto 6868\"

echo \"\\n📝 4. Logs recientes de Placement:\"
journalctl -u placement-api --no-pager -n 10 | tail -5

echo \"\\n⚙️  5. Configuración de Placement en nova.conf:\"
grep -A5 -B2 '\\[placement\\]' /etc/nova/nova.conf || echo \"❌ Sección [placement] no encontrada\"
HEADNODE_CHECK"

echo -e "\n🖥️  2. Verificando compute nodes..."
for port in 5822 5823 5824; do
    worker_name="worker$((port-5821))"
    echo "--- Verificando $worker_name (puerto $port) ---"
    
    ssh ubuntu@10.20.12.187 -p $port << WORKER_CHECK
echo "Worker: \$(hostname)"
echo "🔧 Configuración de Placement en nova.conf:"
grep -A10 '\[placement\]' /etc/nova/nova.conf 2>/dev/null || echo "❌ Sección [placement] no encontrada"

echo -e "\n📊 Estado de nova-compute:"
systemctl is-active nova-compute && echo "✅ nova-compute: RUNNING" || echo "❌ nova-compute: NOT RUNNING"

echo -e "\n📝 Logs recientes de nova-compute:"
journalctl -u nova-compute --no-pager -n 5 | grep -i "placement\|error" | tail -3
WORKER_CHECK
done

echo -e "\n🛠️  3. Comandos para arreglar Placement API:"
echo "Ejecuta estos comandos EN EL HEADNODE (10.60.2.21):"
echo ""
echo "# 1. Verificar que Placement API esté instalado:"
echo "ssh ubuntu@10.20.12.187 -p 5821 'ssh ubuntu@10.60.2.21'"
echo "sudo apt list --installed | grep placement"
echo ""
echo "# 2. Si no está instalado, instalarlo:"
echo "sudo apt install placement-api -y"
echo ""
echo "# 3. Verificar configuración de Placement:"
echo "sudo grep -A10 '[placement]' /etc/nova/nova.conf"
echo ""
echo "# 4. Reiniciar servicios Nova:"
echo "sudo systemctl restart nova-api nova-scheduler nova-conductor"
echo ""
echo "# 5. Reiniciar Placement API:"
echo "sudo systemctl restart placement-api"
echo "sudo systemctl enable placement-api"
echo ""
echo "# 6. Verificar que Placement responda:"
echo "curl -I http://localhost:6868/"
echo ""
echo "# 7. Sincronizar base de datos de Placement:"
echo "sudo su -s /bin/sh -c 'placement-manage db sync' placement"
echo ""
echo "# 8. Descubrir compute hosts:"
echo "sudo su -s /bin/sh -c 'nova-manage cell_v2 discover_hosts --verbose' nova"
