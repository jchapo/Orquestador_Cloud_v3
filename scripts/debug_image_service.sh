#!/bin/bash
# debug_image_service.sh

echo "🔧 Debugging Image Service..."

# 1. Verificar que el servicio está corriendo
echo "📊 Estado del servicio:"
sudo systemctl status pucp-image-service --no-pager -l

# 2. Ver logs en tiempo real
echo "📋 Últimos logs del Image Service:"
sudo journalctl -u pucp-image-service --no-pager -n 20

# 3. Probar con token del auth service
echo "🔐 Obteniendo token fresco..."
TOKEN=$(curl -s -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}')

echo "Respuesta de auth:"
echo $TOKEN | jq '.'

JWT_TOKEN=$(echo $TOKEN | jq -r '.token')

# 4. Probar directamente el endpoint
echo "🧪 Probando endpoint de images..."
echo "URL: http://localhost:5005/api/images"
echo "Token: ${JWT_TOKEN:0:30}..."

# Hacer request con verbose para ver detalles
curl -v -H "Authorization: Bearer $JWT_TOKEN" http://localhost:5005/api/images

echo ""
echo "🔍 Verificando logs después del request..."
sudo journalctl -u pucp-image-service --no-pager -n 5
