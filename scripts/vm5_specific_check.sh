#!/bin/bash

echo "=== VERIFICACIÓN ESPECÍFICA DE VM5 ==="
echo ""

# Conectar a server1 donde está vm5
echo "1. INFORMACIÓN DETALLADA DE VM5:"
echo "==============================="

# Estado de vm5
echo "Estado de vm5:"
ssh ubuntu@pucp-server1 "sudo virsh domstate vm5"
echo ""

# Información de la VM
echo "Información de vm5:"
ssh ubuntu@pucp-server1 "sudo virsh dominfo vm5"
echo ""

# Interfaces de red de vm5
echo "Interfaces de red de vm5:"
ssh ubuntu@pucp-server1 "sudo virsh domiflist vm5"
echo ""

# Intentar obtener dirección IP
echo "Direcciones IP de vm5:"
ssh ubuntu@pucp-server1 "sudo virsh domifaddr vm5"
echo ""

# 2. Configuración de la VLAN 101 (usada por vm5)
echo "2. CONFIGURACIÓN DE VLAN 101:"
echo "============================="

echo "Configuración de vlan101:"
ssh ubuntu@pucp-server1 "ip addr show vlan101"
echo ""

echo "Estado de OVS para vlan101:"
ssh ubuntu@pucp-server1 "sudo ovs-vsctl list-ports ovs1 | grep vlan101"
echo ""

# 3. Verificar NAT y routing para vm5
echo "3. NAT Y ROUTING PARA VM5:"
echo "=========================="

echo "Reglas NAT específicas para 10.60.1.0/24:"
ssh ubuntu@pucp-server1 "sudo iptables -t nat -L POSTROUTING -n -v | grep '10.60.1'"
echo ""

echo "Reglas FORWARD para 10.60.1.0/24:"
ssh ubuntu@pucp-server1 "sudo iptables -L FORWARD -n -v | grep '10.60.1'"
echo ""

# 4. Probar conectividad desde el host
echo "4. CONECTIVIDAD DESDE EL HOST:"
echo "============================="

# Obtener IP de vm5 de manera más robusta
VM5_IP=$(ssh ubuntu@pucp-server1 "sudo virsh domifaddr vm5 --source lease" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)

if [ -z "$VM5_IP" ]; then
    VM5_IP=$(ssh ubuntu@pucp-server1 "sudo virsh domifaddr vm5 --source agent" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
fi

if [ -n "$VM5_IP" ]; then
    echo "IP detectada de vm5: $VM5_IP"
    echo ""
    
    echo "Ping desde server1 a vm5:"
    ssh ubuntu@pucp-server1 "ping -c 3 $VM5_IP"
    echo ""
    
    echo "Intentando SSH a vm5 (si está habilitado):"
    ssh ubuntu@pucp-server1 "timeout 5 ssh -o ConnectTimeout=3 ubuntu@$VM5_IP 'echo \"SSH OK\"' 2>/dev/null || echo 'SSH no disponible o timeout'"
    echo ""
else
    echo "No se pudo detectar IP de vm5"
    echo ""
    
    echo "Verificando DHCP leases:"
    ssh ubuntu@pucp-server1 "sudo grep vm5 /var/lib/dhcp/dhcpd.leases 2>/dev/null | tail -5"
    echo ""
    
    echo "Verificando ARP table:"
    ssh ubuntu@pucp-server1 "arp -a | grep '10.60.1'"
    echo ""
fi

# 5. Información para acceso VNC
echo "5. ACCESO VNC:"
echo "============="

echo "Puerto VNC de vm5:"
VNC_PORT=$(ssh ubuntu@pucp-server1 "sudo virsh dumpxml vm5 | grep \"graphics type='vnc'\" | grep -oE \"port='[0-9]+\"| cut -d\"'\" -f2")

if [ -n "$VNC_PORT" ]; then
    echo "Puerto VNC de vm5: $VNC_PORT"
    echo "Para conectar desde tu laptop: vnc://10.20.12.16:5811"
    echo "(El puerto 5811 está mapeado al servidor server1)"
else
    echo "No se pudo determinar puerto VNC"
fi
echo ""

# 6. Comandos para probar conectividad saliente desde vm5
echo "6. COMANDOS PARA PROBAR EN VM5:"
echo "==============================="
echo ""
echo "Una vez que te conectes a vm5 (por VNC o SSH), ejecuta estos comandos:"
echo ""
echo "# Verificar interfaz de red:"
echo "ip addr show"
echo ""
echo "# Verificar ruta por defecto:"
echo "ip route show"
echo ""
echo "# Probar conectividad a internet:"
echo "ping -c 3 8.8.8.8"
echo ""
echo "# Probar resolución DNS:"
echo "nslookup google.com"
echo ""
echo "# Probar HTTP:"
echo "curl -I http://google.com"
echo ""
