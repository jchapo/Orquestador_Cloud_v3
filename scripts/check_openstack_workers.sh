#!/bin/bash

echo "🔍 Verificando workers de OpenStack..."

WORKERS=(
    "worker1:10.60.2.22:5822"
    "worker2:10.60.2.23:5823" 
    "worker3:10.60.2.24:5824"
)

for worker_info in "${WORKERS[@]}"; do
    worker_name=$(echo $worker_info | cut -d: -f1)
    worker_ip=$(echo $worker_info | cut -d: -f2)
    worker_port=$(echo $worker_info | cut -d: -f3)
    
    echo "=== Verificando $worker_name ($worker_ip) ==="
    
    # Verificar via gateway
    ssh -o ConnectTimeout=10 ubuntu@10.20.12.187 -p 5821 "ssh -o ConnectTimeout=5 ubuntu@$worker_ip << 'WORKER_CHECK'
echo \"Worker: \$(hostname)\"
echo \"Nova compute:\"
if systemctl is-active --quiet nova-compute 2>/dev/null; then
    echo \"  ✅ nova-compute: RUNNING\"
else
    echo \"  ❌ nova-compute: NOT RUNNING\"
fi

echo \"Neutron agent:\"
if systemctl is-active --quiet neutron-openvswitch-agent 2>/dev/null; then
    echo \"  ✅ neutron-openvswitch-agent: RUNNING\"
else
    echo \"  ❌ neutron-openvswitch-agent: NOT RUNNING\"
fi

echo \"Libvirt:\"
if systemctl is-active --quiet libvirtd 2>/dev/null; then
    echo \"  ✅ libvirtd: RUNNING\"
else
    echo \"  ❌ libvirtd: NOT RUNNING\"
fi
WORKER_CHECK" 2>/dev/null || echo "❌ No se pudo conectar a $worker_name"
    
    echo ""
done
