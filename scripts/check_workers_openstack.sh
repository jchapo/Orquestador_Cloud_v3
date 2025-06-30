#!/bin/bash

echo "🔍 Verificando servicios OpenStack en workers accesibles..."

WORKERS=("5822:worker1" "5823:worker2" "5824:worker3")

for worker_info in "${WORKERS[@]}"; do
    port=$(echo $worker_info | cut -d: -f1)
    worker_name=$(echo $worker_info | cut -d: -f2)
    
    echo "=== Verificando $worker_name (puerto $port) ==="
    
    ssh ubuntu@10.20.12.187 -p $port << WORKER_CHECK
echo "Hostname: \$(hostname)"
echo "IP: \$(hostname -I)"

echo "1. Servicios OpenStack Controller:"
for service in apache2 keystone nova-api neutron-server glance-api; do
    if systemctl is-active --quiet \$service 2>/dev/null; then
        echo "  ✅ \$service: RUNNING"
    else
        echo "  ❌ \$service: NOT RUNNING"
    fi
done

echo ""
echo "2. Servicios OpenStack Compute:"
for service in nova-compute neutron-openvswitch-agent libvirtd; do
    if systemctl is-active --quiet \$service 2>/dev/null; then
        echo "  ✅ \$service: RUNNING"
    else
        echo "  ❌ \$service: NOT RUNNING"
    fi
done

echo ""
echo "3. Puertos OpenStack:"
netstat -tlnp 2>/dev/null | grep -E "(5000|8774|9292|9696)" || echo "  No hay puertos OpenStack"

echo ""
echo "4. Test HTTP local:"
curl -s -m 3 http://localhost:5000/v3 2>/dev/null | head -2 || echo "  No hay Keystone local"

echo "========================"
WORKER_CHECK
done
