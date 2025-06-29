#!/bin/bash

set -e  # Exit on any error

echo "🚀 PUCP Cloud Orchestrator - Test de VM con Acceso Externo"
echo "=========================================================="

# Configuración
API_BASE="http://localhost/api"
USERNAME="testuser"
PASSWORD="testpass123"

# Función para logging con timestamp
log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# 1. Autenticación
log "🔐 Autenticando con el sistema..."
AUTH_RESPONSE=$(curl -s -X POST $API_BASE/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")

TOKEN=$(echo $AUTH_RESPONSE | jq -r '.token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
    log "❌ Error de autenticación"
    echo $AUTH_RESPONSE | jq '.'
    exit 1
fi

log "✅ Autenticado exitosamente"

# 2. Verificar recursos
log "📊 Verificando recursos disponibles..."
RESOURCES=$(curl -s -H "Authorization: Bearer $TOKEN" \
  $API_BASE/resources?infrastructure=linux)

AVAILABLE_SERVERS=$(echo $RESOURCES | jq -r '.servers | length')
log "   Servidores disponibles: $AVAILABLE_SERVERS"

if [ "$AVAILABLE_SERVERS" -eq 0 ]; then
    log "❌ No hay servidores disponibles"
    exit 1
fi

# Mostrar recursos
echo $RESOURCES | jq '.servers[] | {hostname, available_vcpus, available_ram, status}'

# 3. Crear slice
log "🏗️ Creando slice de prueba..."
SLICE_DATA='{
  "name": "laptop-access-'$(date +%s)'",
  "description": "VM de prueba para acceso desde laptop",
  "infrastructure": "linux",
  "placement_policy": "balanced",
  "nodes": [
    {
      "name": "vm-test-external",
      "image": "ubuntu-20.04",
      "flavor": "small",
      "internet_access": true
    }
  ],
  "networks": [
    {
      "name": "test-external-net",
      "cidr": "10.60.1.0/24",
      "gateway": "10.60.1.1",
      "network_type": "trunk",
      "internet_access": true
    }
  ],
  "connections": []
}'

SLICE_RESPONSE=$(curl -s -X POST $API_BASE/slices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$SLICE_DATA")

SLICE_ID=$(echo $SLICE_RESPONSE | jq -r '.id')

if [ "$SLICE_ID" = "null" ] || [ -z "$SLICE_ID" ]; then
    log "❌ Error creando slice"
    echo $SLICE_RESPONSE | jq '.'
    exit 1
fi

log "✅ Slice creado exitosamente: $SLICE_ID"

# 4. Desplegar
log "🚀 Iniciando deployment..."
DEPLOY_RESPONSE=$(curl -s -X POST $API_BASE/slices/$SLICE_ID/deploy \
  -H "Authorization: Bearer $TOKEN")

# Reemplaza la línea problemática con:
DEPLOY_STATUS=$(echo "$DEPLOY_RESPONSE" | jq -r '.status // "unknown"' 2>/dev/null || echo "error")

# Y agrega debugging:
if [ "$DEPLOY_STATUS" = "unknown" ] || [ "$DEPLOY_STATUS" = "error" ]; then
    log "❌ Respuesta de deployment inválida:"
    echo "$DEPLOY_RESPONSE"
    exit 1
fi

# 5. Monitorear progreso
log "👀 Monitoreando progreso del deployment..."
MAX_ATTEMPTS=30
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    sleep 10
    
    STATUS_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
      $API_BASE/slices/$SLICE_ID)
    
    STATUS=$(echo $STATUS_RESPONSE | jq -r '.status')
    
    case $STATUS in
        "active")
            log "✅ ¡Deployment completado exitosamente!"
            echo ""
            echo "🔗 INFORMACIÓN DE ACCESO:"
            echo "========================"
            
            # Extraer información de la VM
            VM_INFO=$(echo $STATUS_RESPONSE | jq '.nodes[0]')
            VM_NAME=$(echo $VM_INFO | jq -r '.name')
            VM_IP=$(echo $VM_INFO | jq -r '.ip_address // "Pendiente"')
            VM_STATUS=$(echo $VM_INFO | jq -r '.status')
            CONSOLE_URL=$(echo $VM_INFO | jq -r '.console_url // "N/A"')
            
            echo "VM: $VM_NAME"
            echo "Estado: $VM_STATUS"
            echo "IP interna: $VM_IP"
            echo "Consola VNC: $CONSOLE_URL"
            echo ""
            
            # Información de acceso externo
            echo "🌐 ACCESO DESDE TU LAPTOP:"
            echo "========================="
            echo "Comando SSH: ssh ubuntu@10.60.1.1 -p 2201"
            echo "Nota: El puerto específico puede variar según la configuración"
            echo ""
            
            # Información para cleanup
            echo "🧹 PARA LIMPIAR:"
            echo "================"
            echo "Slice ID: $SLICE_ID"
            echo "Comando: curl -X DELETE -H \"Authorization: Bearer $TOKEN\" $API_BASE/slices/$SLICE_ID"
            echo ""
            
            log "🎉 Test completado exitosamente!"
            exit 0
            ;;
        "error")
            log "❌ Error en deployment:"
            ERROR_MSG=$(echo $STATUS_RESPONSE | jq -r '.error_message // "Error desconocido"')
            echo "   $ERROR_MSG"
            exit 1
            ;;
        "deploying"|"validating")
            log "   ⏳ $STATUS... ($ATTEMPT/$MAX_ATTEMPTS)"
            ;;
        *)
            log "   ℹ️ Estado: $STATUS ($ATTEMPT/$MAX_ATTEMPTS)"
            ;;
    esac
    
    ((ATTEMPT++))
done

log "⏰ Timeout después de $((MAX_ATTEMPTS * 10)) segundos"
log "   Estado final: $STATUS"
exit 1
