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
  "name": "test-vm-complete-'$(date +%s)'",
  "description": "VM de prueba con información completa de acceso",
  "infrastructure": "linux",
  "placement_policy": "balanced",
  "nodes": [
    {
      "name": "vm-test-complete",
      "image": "ubuntu-20.04",
      "flavor": "small",
      "internet_access": true
    }
  ],
  "networks": [
    {
      "name": "test-net-complete",
      "cidr": "10.60.1.0/24",
      "gateway": "10.60.1.1",
      "network_type": "trunk",
      "internet_access": true
    }
  ]
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
VM_INFO=$(echo $FINAL_RESPONSE | jq '.nodes[0]')
VM_NAME=$(echo $VM_INFO | jq -r '.name')
VM_IP=$(echo $VM_INFO | jq -r '.ip_address // "Asignada dinámicamente"')
VM_STATUS=$(echo $VM_INFO | jq -r '.status')
CONSOLE_URL=$(echo $VM_INFO | jq -r '.console_url // "N/A"')
ASSIGNED_HOST=$(echo $VM_INFO | jq -r '.assigned_host // "N/A"')

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
echo "📋 INFORMACIÓN DE LA VM:"
echo "========================"
echo "Nombre: $VM_NAME"
echo "Estado: $VM_STATUS"
echo "Servidor asignado: $ASSIGNED_HOST"
echo "IP interna: $VM_IP"
echo "Consola VNC: $CONSOLE_URL"
echo ""
echo "🌐 INFORMACIÓN DE RED:"
echo "======================"
echo "Red: $NETWORK_NAME"
echo "CIDR: $NETWORK_CIDR"
echo "Gateway: $NETWORK_GATEWAY"
echo "VLAN ID: $VLAN_ID"
echo ""
echo "🔌 ACCESO DESDE TU LAPTOP:"
echo "=========================="
echo ""
echo "La VM está configurada con acceso a internet y se encuentra en la VLAN $VLAN_ID"
echo "Para acceder desde tu laptop a través de la VPN:"
echo ""
echo "1. Conectar a la VPN de PUCP"
echo "2. La VM debería ser accesible a través del gateway: $NETWORK_GATEWAY"
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

# Mostrar datos técnicos del deployment si están disponibles
if echo "$DEPLOYED_VMS" | jq -e '. | length > 0' > /dev/null 2>&1; then
    echo "📊 DATOS TÉCNICOS DEL DEPLOYMENT:"
    echo "================================="
    echo "$DEPLOYED_VMS" | jq -r '.[] | "VM: \(.name)\nServidor: \(.server)\nID VM: \(.vm_id // "N/A")\nIP: \(.ip_address // "Dinámica")\nConsola: \(.console_url // "N/A")\n"'
fi

log "🎉 Test completado exitosamente!"