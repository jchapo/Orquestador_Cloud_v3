#!/bin/bash
# test_fixed_image_service.sh

echo "🧪 Probando Image Service corregido..."

# 1. Ejecutar fix
chmod +x fix_image_service_complete.sh
./fix_image_service_complete.sh

# 2. Esperar que arranque completamente
echo "⏳ Esperando que el servicio arranque..."
sleep 5

# 3. Obtener token fresco
echo "🔐 Obteniendo token..."
TOKEN=$(curl -s -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')

echo "Token obtenido: ${TOKEN:0:30}..."

# 4. Probar endpoint
echo "🧪 Probando endpoint /api/images..."
RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost:5005/api/images)
echo "Respuesta:"
echo $RESPONSE | jq '.' || echo $RESPONSE

# 5. Ver logs recientes
echo "📋 Logs recientes del Image Service:"
sudo journalctl -u pucp-image-service --no-pager -n 10

# 6. Si funciona, probar a través del API Gateway
if echo $RESPONSE | jq -e '.' > /dev/null 2>&1; then
  echo "✅ Image Service funcionando directamente!"
  
  echo "🌐 Probando a través del API Gateway..."
  GATEWAY_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" http://localhost/api/images)
  echo "Respuesta del Gateway:"
  echo $GATEWAY_RESPONSE | jq '.' || echo $GATEWAY_RESPONSE
else
  echo "❌ Image Service aún no funciona"
fi
