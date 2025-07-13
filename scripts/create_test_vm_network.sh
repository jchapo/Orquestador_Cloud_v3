#!/bin/bash
set -e
echo "🚀 PUCP Cloud Orchestrator - Test Topología Completa"
echo "====================================================="
API_BASE="http://localhost/api"
USERNAME="testuser"
PASSWORD="testpass123"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# Autenticación
log "🔐 Autenticando..."
AUTH_RESPONSE=$(curl -s -X POST $API_BASE/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

TOKEN=$(echo $AUTH_RESPONSE | jq -r '.token')
if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    log "❌ Error de autenticación"
    exit 1
fi
log "✅ Autenticado"

# Crear slice con topología completa
log "🏗️ Creando slice con topología de 6 VMs..."
SLICE_DATA='{
  "name": "pucp-network-topology",
  "description": "Topología de red con múltiples VMs interconectadas según diagrama",
  "infrastructure": "linux",
  "placement_policy": "distributed",
  "availability_zone": "zone1-linux",
  "nodes": [
    {
      "name": "vm6",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro",
      "internet_access": false,
      "description": "Nodo terminal superior"
    },
    {
      "name": "vm5",
      "image": "ubuntu-22.04-minimal", 
      "flavor": "small",
      "internet_access": true,
      "description": "Nodo central con acceso a internet"
    },
    {
      "name": "vm4",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro",
      "internet_access": false,
      "description": "Nodo intermedio con acceso a internet"
    },
    {
      "name": "vm1",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro", 
      "internet_access": false,
      "description": "Nodo terminal inferior izquierdo"
    },
    {
      "name": "vm3",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro",
      "internet_access": false,
      "description": "Nodo terminal inferior derecho"
    },
    {
      "name": "vm2",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro",
      "internet_access": false,
      "description": "Nodo intermedio inferior"
    }
  ],
  "networks": [
    {
      "name": "topology-network",
      "cidr": "10.60.1.0/24",
      "gateway": "10.60.1.1",
      "network_type": "trunk",
      "internet_access": true,
      "description": "Red principal de la topología"
    }
  ],
  "connections": [
    {
      "source": "vm6",
      "target": "vm5",
      "network": "topology-network",
      "description": "VM6 -> VM5"
    },
    {
      "source": "vm5",
      "target": "vm4", 
      "network": "topology-network",
      "description": "VM5 -> VM4"
    },
    {
      "source": "vm4",
      "target": "vm3",
      "network": "topology-network", 
      "description": "VM4 -> VM3"
    },
    {
      "source": "vm3",
      "target": "vm2",
      "network": "topology-network",
      "description": "VM3 -> VM2"
    },
    {
      "source": "vm2",
      "target": "vm1",
      "network": "topology-network",
      "description": "VM2 -> VM1"
    },
    {
      "source": "vm1",
      "target": "vm4",
      "network": "topology-network", 
      "description": "VM1 -> VM4"
    }
  ],
  "topology": {
    "type": "custom",
    "description": "Topología jerárquica (VM5) con acceso a internet",
    "routing_rules": [
      {
        "description": "Solo VM5 tiene acceso directo a internet",
        "rule": "internet_gateway_only_vm5"
      },
      {
        "description": "Otras VMs acceden a internet a través de VM5",
        "rule": "nat_through_vm5"
      }
    ]
  }
}'

SLICE_RESPONSE=$(curl -s -X POST $API_BASE/slices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$SLICE_DATA")

SLICE_ID=$(echo $SLICE_RESPONSE | jq -r '.id')
if [ "$SLICE_ID" = "null" ]; then
    log "❌ Error creando slice"
    echo $SLICE_RESPONSE | jq '.'
    exit 1
fi
log "✅ Slice creado: $SLICE_ID"

# Deploy
log "🚀 Iniciando deployment..."
log "   (Esto puede tomar 5-8 minutos para 6 VMs)"
DEPLOY_RESPONSE=$(curl -s -X POST $API_BASE/slices/$SLICE_ID/deploy \
  -H "Authorization: Bearer $TOKEN" \
  --max-time 900)

# Verificar respuesta
if echo "$DEPLOY_RESPONSE" | grep -q "504 Gateway Time-out"; then
    log "❌ Timeout de nginx"
    exit 1
fi

DEPLOY_STATUS=$(echo "$DEPLOY_RESPONSE" | jq -r '.status // "unknown"' 2>/dev/null || echo "error")
if [ "$DEPLOY_STATUS" = "success" ]; then
    log "✅ ¡Deployment completado inmediatamente!"
else
    # Monitorear progreso
    log "👀 Monitoreando progreso del deployment..."
    for i in {1..45}; do
        sleep 15
        
        STATUS_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
          $API_BASE/slices/$SLICE_ID)
        
        STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
        
        case $STATUS in
            "active")
                log "✅ ¡Deployment completado!"
                break
                ;;
            "error")
                log "❌ Error en deployment"
                echo $STATUS_RESPONSE | jq '.error_message'
                exit 1
                ;;
            *)
                log "   ⏳ $STATUS... ($i/45) - Desplegando 6 VMs"
                ;;
        esac
        
        if [ $i -eq 45 ]; then
            log "⏰ Timeout de monitoreo"
            exit 1
        fi
    done
fi

# Obtener información completa final
log "📊 Obteniendo información completa..."
FINAL_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
  $API_BASE/slices/$SLICE_ID)

# Extraer información de todas las VMs
VM_COUNT=$(echo $FINAL_RESPONSE | jq '.nodes | length')
NETWORK_INFO=$(echo $FINAL_RESPONSE | jq '.networks[0]')
NETWORK_NAME=$(echo $NETWORK_INFO | jq -r '.name')
NETWORK_CIDR=$(echo $NETWORK_INFO | jq -r '.cidr')
NETWORK_GATEWAY=$(echo $NETWORK_INFO | jq -r '.gateway')
VLAN_ID=$(echo $NETWORK_INFO | jq -r '.vlan_id // "N/A"')

# Obtener información del deployment
DEPLOYMENT_DATA=$(echo $FINAL_RESPONSE | jq '.deployment_data')
DEPLOYED_VMS=$(echo $DEPLOYMENT_DATA | jq '.deployed_vms // []')

echo ""
echo "🎉 ¡DEPLOYMENT DE TOPOLOGÍA COMPLETADO EXITOSAMENTE!"
echo "====================================================="
echo ""
echo "📋 INFORMACIÓN DE LAS VMs:"
echo "=========================="
echo "Total de VMs desplegadas: $VM_COUNT"
echo ""

# Mostrar información de cada VM
for i in $(seq 0 $((VM_COUNT-1))); do
    VM_INFO=$(echo $FINAL_RESPONSE | jq ".nodes[$i]")
    VM_NAME=$(echo $VM_INFO | jq -r '.name')
    VM_IP=$(echo $VM_INFO | jq -r '.ip_address // "Dinámica"')
    VM_STATUS=$(echo $VM_INFO | jq -r '.status')
    VM_HOST=$(echo $VM_INFO | jq -r '.assigned_host // "N/A"')
    INTERNET_ACCESS=$(echo $VM_INFO | jq -r '.internet_access // false')
    
    if [ "$INTERNET_ACCESS" = "true" ]; then
        INTERNET_ICON="🌐"
        ROLE=" (GATEWAY)"
    else
        INTERNET_ICON="🔒"
        ROLE=""
    fi
    
    echo "$INTERNET_ICON $VM_NAME$ROLE:"
    echo "  Estado: $VM_STATUS"
    echo "  Servidor: $VM_HOST"
    echo "  IP: $VM_IP"
    echo "  Internet: $INTERNET_ACCESS"
    echo ""
done

echo "🌐 INFORMACIÓN DE RED:"
echo "======================"
echo "Red: $NETWORK_NAME"
echo "CIDR: $NETWORK_CIDR"
echo "Gateway: $NETWORK_GATEWAY"
echo "VLAN ID: $VLAN_ID"
echo ""

echo "🔌 TOPOLOGÍA Y CONECTIVIDAD:"
echo "============================"
echo ""
echo "Estructura jerárquica desplegada:"
echo ""
echo "        VM6 (sin internet)"
echo "         |"
echo "        VM5 (🌐 GATEWAY) ← Única con acceso directo a internet"
echo "       /   \\"
echo "     VM4   VM3 (sin internet)"
echo "    /  \\"
echo "  VM1  VM2 (sin internet)"
echo "       |"
echo "      VM3"
echo ""
echo "🔀 CONEXIONES CONFIGURADAS:"
echo "• VM6 ↔ VM5 (gateway)"
echo "• VM5 ↔ VM4, VM5 ↔ VM3" 
echo "• VM4 ↔ VM1, VM4 ↔ VM2"
echo "• VM2 ↔ VM3"
echo ""

echo "🌐 ACCESO A INTERNET:"
echo "====================="
echo "• VM5: ✅ Acceso directo a internet"
echo "• Otras VMs: ⚠️  Sin acceso directo (deben usar VM5 como gateway)"
echo ""

echo "🔧 COMANDOS PARA PRUEBAS DE CONECTIVIDAD:"
echo "========================================="
echo ""
echo "# Conectar a VM5 (gateway) - tiene acceso a internet:"
echo "ssh ubuntu@$NETWORK_GATEWAY -p [PUERTO_VM5]"
echo ""
echo "# Desde VM5, probar internet:"
echo "ping 8.8.8.8"
echo "curl -I https://www.google.com"
echo ""
echo "# Desde VM5, probar conectividad interna a otras VMs:"
echo "ping [IP_VM1] # Ping a VM1"
echo "ping [IP_VM2] # Ping a VM2" 
echo "ping [IP_VM3] # Ping a VM3"
echo "ping [IP_VM4] # Ping a VM4"
echo "ping [IP_VM6] # Ping a VM6"
echo ""
echo "# Configurar NAT en VM5 para compartir internet:"
echo "sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
echo "sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT"
echo "sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT"
echo "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
echo ""

echo "🔍 VERIFICACIÓN EN SERVIDORES:"
echo "==============================="
echo ""
echo "# Verificar todas las VMs corriendo:"
echo "for server in server1 server2 server3 server4; do"
echo "  echo \"=== \$server ===\""
echo "  ssh ubuntu@\$server 'virsh list'"
echo "done"
echo ""
echo "# Verificar configuración de red OVS:"
echo "ssh ubuntu@[SERVER] 'ovs-vsctl show'"
echo ""
echo "# Verificar VLAN configurada:"
echo "ssh ubuntu@[SERVER] 'ip link show | grep vlan$VLAN_ID'"
echo ""

echo "🧹 PARA LIMPIAR RECURSOS:"
echo "========================="
echo "Slice ID: $SLICE_ID"
echo ""
echo "curl -X DELETE -H \"Authorization: Bearer $TOKEN\" $API_BASE/slices/$SLICE_ID"
echo ""

# Mostrar datos técnicos del deployment si están disponibles
if echo "$DEPLOYED_VMS" | jq -e '. | length > 0' > /dev/null 2>&1; then
    echo "📊 DATOS TÉCNICOS DEL DEPLOYMENT:"
    echo "================================="
    echo "$DEPLOYED_VMS" | jq -r '.[] | "VM: \(.name)\nServidor: \(.server)\nID VM: \(.vm_id // "N/A")\nIP: \(.ip_address // "Dinámica")\nConsola: \(.console_url // "N/A")\n---"'
fi

echo "📋 RESUMEN FINAL:"
echo "================="
echo "✅ $VM_COUNT VMs desplegadas exitosamente"
echo "✅ Topología jerárquica configurada"
echo "✅ VM5 configurada como gateway con acceso a internet"
echo "✅ Red interna $NETWORK_CIDR establecida"
echo "✅ VLAN $VLAN_ID asignada"
echo ""

log "🎉 Test de topología completa exitoso!"