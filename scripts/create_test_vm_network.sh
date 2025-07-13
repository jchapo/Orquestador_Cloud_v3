#!/bin/bash
set -e

echo "🚀 PUCP Cloud Orchestrator - Test VM Complete"
echo "=============================================="

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

# Crear slice
log "🏗️ Creando slice..."
SLICE_DATA='{
  "name": "test-topologia-lineal-'$(date +%s)'",
  "description": "Topología lineal: VM1 (sin internet) ↔ VM2 (con internet)",
  "infrastructure": "linux",
  "placement_policy": "distributed",
  "nodes": [
    {
      "name": "vm1-sin-internet",
      "image": "ubuntu-22.04-minimal", 
      "flavor": "micro",
      "internet_access": false
    },
    {
      "name": "vm2-con-internet",
      "image": "ubuntu-22.04-minimal",
      "flavor": "micro", 
      "internet_access": true
    }
  ],
  "networks": [
    {
      "name": "topologia-lineal",
      "cidr": "10.60.1.0/24",
      "gateway": "10.60.1.1", 
      "network_type": "trunk",
      "internet_access": false
    }
  ],
  "topology": {
    "type": "linear",
    "connections": [
      {
        "from": "vm1-sin-internet",
        "to": "vm2-con-internet",
        "network": "topologia-lineal"
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
log "   (Esto puede tomar 3-5 minutos)"

DEPLOY_RESPONSE=$(curl -s -X POST $API_BASE/slices/$SLICE_ID/deploy \
  -H "Authorization: Bearer $TOKEN" \
  --max-time 600)

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
    log "👀 Monitoreando progreso..."
    for i in {1..30}; do
        sleep 10
        
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
                log "   ⏳ $STATUS... ($i/30)"
                ;;
        esac
        
        if [ $i -eq 30 ]; then
            log "⏰ Timeout de monitoreo"
            exit 1
        fi
    done
fi

# Obtener información completa final
log "📊 Obteniendo información completa..."
FINAL_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
  $API_BASE/slices/$SLICE_ID)

# Extraer información de la VM
VM1_INFO=$(echo $FINAL_RESPONSE | jq '.nodes[0]')
VM2_INFO=$(echo $FINAL_RESPONSE | jq '.nodes[1]')
VM1_NAME=$(echo $VM1_INFO | jq -r '.name')
VM1_IP=$(echo $VM1_INFO | jq -r '.ip_address // "Dinámica"')
VM1_STATUS=$(echo $VM1_INFO | jq -r '.status')
VM1_HOST=$(echo $VM1_INFO | jq -r '.assigned_host // "N/A"')

VM2_NAME=$(echo $VM2_INFO | jq -r '.name')
VM2_IP=$(echo $VM2_INFO | jq -r '.ip_address // "Dinámica"')
VM2_STATUS=$(echo $VM2_INFO | jq -r '.status')
VM2_HOST=$(echo $VM2_INFO | jq -r '.assigned_host // "N/A"')
VM2_CONSOLE=$(echo $VM2_INFO | jq -r '.console_url // "N/A"')

# Extraer información de la red
NETWORK_INFO=$(echo $FINAL_RESPONSE | jq '.networks[0]')
NETWORK_NAME=$(echo $NETWORK_INFO | jq -r '.name')
NETWORK_CIDR=$(echo $NETWORK_INFO | jq -r '.cidr')
NETWORK_GATEWAY=$(echo $NETWORK_INFO | jq -r '.gateway')
VLAN_ID=$(echo $NETWORK_INFO | jq -r '.vlan_id // "N/A"')

# Obtener información del deployment
DEPLOYMENT_DATA=$(echo $FINAL_RESPONSE | jq '.deployment_data')
DEPLOYED_VMS=$(echo $DEPLOYMENT_DATA | jq '.deployed_vms // []')

echo ""
echo "🎉 ¡DEPLOYMENT COMPLETADO EXITOSAMENTE!"
echo "======================================="
echo ""
echo "📋 INFORMACIÓN DE LAS VMs:"
echo "=========================="
echo "VM1 (sin internet):"
echo "  Nombre: $VM1_NAME"
echo "  Estado: $VM1_STATUS"
echo "  Servidor: $VM1_HOST"
echo "  IP: $VM1_IP"
echo "  Acceso externo: ❌ NO"
echo ""
echo "VM2 (con internet):"
echo "  Nombre: $VM2_NAME"
echo "  Estado: $VM2_STATUS"
echo "  Servidor: $VM2_HOST"
echo "  IP: $VM2_IP"
echo "  Consola VNC: $VM2_CONSOLE"
echo "  Acceso externo: ✅ SÍ"
echo ""
echo "🌐 INFORMACIÓN DE RED:"
echo "======================"
echo "Red: $NETWORK_NAME"
echo "CIDR: $NETWORK_CIDR"
echo "Gateway: $NETWORK_GATEWAY"
echo "VLAN ID: $VLAN_ID"
echo ""
echo "🔌 ACCESO DESDE TU LAPTOP (VPN PUCP):"
echo "====================================="
echo ""
echo "VM1 ($VM1_NAME):"
echo "  ❌ No accesible desde exterior"
echo "  ✅ Solo comunicación interna con VM2"
echo ""
echo "VM2 ($VM2_NAME):"
echo "  ✅ SSH: ssh ubuntu@192.168.201.1 -p XXXX  # Puerto según servidor"
echo "  ✅ Puede navegar internet"
echo "  ✅ Comunicación con VM1 via $NETWORK_CIDR"
echo ""
echo "🔧 COMANDOS ÚTILES:"
echo "==================="
echo ""
echo "# Verificar estado del slice:"
echo "curl -H \"Authorization: Bearer $TOKEN\" $API_BASE/slices/$SLICE_ID | jq '.status'"
echo ""
echo "# Verificar VMs desplegadas:"
echo "curl -H \"Authorization: Bearer $TOKEN\" $API_BASE/slices/$SLICE_ID | jq '.deployment_data.deployed_vms'"
echo ""
echo "# Conectar por SSH (una vez que la VM esté completamente iniciada):"
echo "ssh ubuntu@$NETWORK_GATEWAY"
echo ""
echo "🧹 PARA LIMPIAR RECURSOS:"
echo "========================="
echo "Slice ID: $SLICE_ID"
echo ""
echo "curl -X DELETE -H \"Authorization: Bearer $TOKEN\" $API_BASE/slices/$SLICE_ID"
echo ""
echo "🔍 VERIFICAR EN LOS SERVIDORES:"
echo "==============================="
echo ""
echo "En el servidor $ASSIGNED_HOST, puedes verificar:"
echo "# Lista de VMs corriendo:"
echo "virsh list"
echo ""
echo "# Estado de la VM específica:"
echo "virsh dominfo $VM_NAME"
echo ""
echo "# Configuración de red OVS:"
echo "ovs-vsctl show"
echo ""
echo "# Verificar VLAN configurada:"
echo "ip link show | grep vlan$VLAN_ID"
echo ""
echo "🧪 VERIFICAR CONECTIVIDAD:"
echo "========================="
echo ""
echo "# Desde VM2, probar ping a VM1:"
echo "ping $VM1_IP"
echo ""
echo "# Desde VM2, probar internet:"
echo "ping 8.8.8.8"
echo ""
echo "# Desde VM1, NO debería tener internet:"
echo "# (Este comando debería fallar)"

# Mostrar datos técnicos del deployment si están disponibles
if echo "$DEPLOYED_VMS" | jq -e '. | length > 0' > /dev/null 2>&1; then
    echo "📊 DATOS TÉCNICOS DEL DEPLOYMENT:"
    echo "================================="
    echo "$DEPLOYED_VMS" | jq -r '.[] | "VM: \(.name)\nServidor: \(.server)\nID VM: \(.vm_id // "N/A")\nIP: \(.ip_address // "Dinámica")\nConsola: \(.console_url // "N/A")\n"'
fi

log "🎉 Test completado exitosamente!"
