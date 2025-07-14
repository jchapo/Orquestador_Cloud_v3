#!/bin/bash

echo "=== VERIFICACIÓN DE CONECTIVIDAD VM5 ==="
echo "Fecha: $(date)"
echo ""

# 1. Verificar estado de las VMs en el slice
echo "1. ESTADO DE LAS VMs EN EL SLICE:"
echo "================================="
echo ""

# Verificar en server1 (donde está vm5)
echo "VMs en server1:"
ssh ubuntu@pucp-server1 "sudo virsh list --all"
echo ""

# Verificar en server2
echo "VMs en server2:"
ssh ubuntu@pucp-server2 "sudo virsh list --all"
echo ""

# 2. Verificar configuración de red OVS
echo "2. CONFIGURACIÓN DE RED OVS:"
echo "==========================="
echo ""

echo "OVS bridges en server1:"
ssh ubuntu@pucp-server1 "sudo ovs-vsctl show"
echo ""

echo "VLAN interfaces en server1:"
ssh ubuntu@pucp-server1 "ip link show | grep vlan"
echo ""

echo "Rutas en server1:"
ssh ubuntu@pucp-server1 "ip route show"
echo ""

# 3. Verificar reglas iptables para NAT
echo "3. REGLAS IPTABLES (NAT):"
echo "========================"
echo ""

echo "Reglas NAT en server1:"
ssh ubuntu@pucp-server1 "sudo iptables -t nat -L -n -v"
echo ""

echo "Reglas FORWARD en server1:"
ssh ubuntu@pucp-server1 "sudo iptables -L FORWARD -n -v"
echo ""

# 4. Verificar conectividad de vm5
echo "4. CONECTIVIDAD DE VM5:"
echo "======================"
echo ""

echo "Intentando obtener IP de vm5..."
VM5_IP=$(ssh ubuntu@pucp-server1 "sudo virsh domifaddr vm5 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1")

if [ -n "$VM5_IP" ]; then
    echo "IP de vm5: $VM5_IP"
    
    echo ""
    echo "Probando conectividad desde server1 a vm5:"
    ssh ubuntu@pucp-server1 "ping -c 3 $VM5_IP"
    
    echo ""
    echo "Probando conectividad de vm5 a internet (si es posible acceder):"
    # Intentar ejecutar comando en vm5 (requiere acceso SSH configurado)
    echo "Nota: Necesitarás acceso SSH a vm5 para probar conectividad saliente"
    
else
    echo "No se pudo obtener IP de vm5 automáticamente"
    echo ""
    echo "Información de interfaces de vm5:"
    ssh ubuntu@pucp-server1 "sudo virsh domifaddr vm5"
    
    echo ""
    echo "DHCP leases:"
    ssh ubuntu@pucp-server1 "sudo cat /var/lib/dhcp/dhcpd.leases 2>/dev/null | tail -20"
fi

# 5. Verificar configuración específica de VLAN 101 (la usada para vm5)
echo ""
echo "5. CONFIGURACIÓN VLAN 101:"
echo "=========================="
echo ""

echo "Estado de vlan101:"
ssh ubuntu@pucp-server1 "ip addr show vlan101 2>/dev/null"
echo ""

echo "Tabla de routing para VLAN 101:"
ssh ubuntu@pucp-server1 "ip route show table 201 2>/dev/null"
echo ""

# 6. Verificar servicios de red
echo "6. SERVICIOS DE RED:"
echo "==================="
echo ""

echo "Estado de dnsmasq:"
ssh ubuntu@pucp-server1 "systemctl status dnsmasq --no-pager -l"
echo ""

echo "IP forwarding habilitado:"
ssh ubuntu@pucp-server1 "cat /proc/sys/net/ipv4/ip_forward"
echo ""

# 7. Información de VNC para conexión externa
echo "7. INFORMACIÓN DE ACCESO VNC:"
echo "============================"
echo ""

echo "Puertos VNC abiertos en server1:"
ssh ubuntu@pucp-server1 "sudo netstat -tulpn | grep ':59'"
echo ""

echo "Configuración VNC de vm5:"
ssh ubuntu@pucp-server1 "sudo virsh dumpxml vm5 | grep -A5 -B5 graphics"
echo ""

echo ""
echo "=== INSTRUCCIONES PARA ACCESO EXTERNO ==="
echo ""
echo "Para conectarte a vm5 desde tu laptop:"
echo "1. VNC: vnc://10.20.12.16:5811 (a través del gateway con port mapping)"
echo "2. SSH: Primero conéctate al gateway, luego al server1, luego a vm5"
echo ""
echo "Para probar conectividad saliente de vm5:"
echo "1. Conéctate por VNC o SSH a vm5"
echo "2. Ejecuta: ping 8.8.8.8"
echo "3. Ejecuta: curl http://google.com"
echo ""
