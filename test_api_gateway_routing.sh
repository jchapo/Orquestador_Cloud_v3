#!/bin/bash
# Test del ruteo del API Gateway

echo "=== Test API Gateway Routing ==="

# 1. Test directo del auth service
echo "1. Test DIRECTO del auth service (puerto 5001):"
echo "Health check:"
curl -s http://localhost:5001/health | python3 -m json.tool

echo ""
echo "Login directo:"
curl -s -X POST http://localhost:5001/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' | python3 -m json.tool

echo ""
echo "2. Test a través del API Gateway (puerto 80):"
echo "Health check gateway:"
curl -s http://localhost/health | python3 -m json.tool

echo ""
echo "Login a través del gateway:"
curl -s -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' | python3 -m json.tool

echo ""
echo "3. Test de registro a través del gateway:"
curl -s -X POST http://localhost/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2",
    "password": "testpass123",
    "email": "test2@pucp.edu.pe",
    "role": "student"
  }' | python3 -m json.tool

echo ""
echo "4. Verificar configuración del API Gateway:"
if [ -f "/opt/pucp-orchestrator/api_gateway.py" ]; then
    echo "API Gateway existe"
    grep -n "AUTH_SERVICE_URL" /opt/pucp-orchestrator/api_gateway.py || echo "AUTH_SERVICE_URL no encontrado"
    grep -n "proxy_request" /opt/pucp-orchestrator/api_gateway.py | head -3
else
    echo "API Gateway no encontrado"
fi

echo ""
echo "5. Verificar procesos activos:"
ps aux | grep -E "(api_gateway|auth_service|gunicorn)" | grep -v grep

echo ""
echo "6. Verificar puertos en uso:"
sudo netstat -tlnp | grep -E ":(80|5000|5001)"
