#!/bin/bash
# Debug del API Gateway

echo "=== Debug API Gateway ==="

# 1. Verificar logs del API Gateway
echo "1. Logs del API Gateway:"
sudo journalctl -u pucp-api-gateway --lines=10 --no-pager

echo ""
echo "2. Logs de Nginx:"
sudo tail -10 /var/log/nginx/error.log

echo ""
echo "3. Verificar qué está corriendo en puerto 80:"
curl -s -I http://localhost/ | head -5

echo ""
echo "4. Test directo del API Gateway en puerto 5000:"
curl -s http://localhost:5000/health | python3 -m json.tool

echo ""
echo "5. Test del proxy en puerto 5000:"
curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' | python3 -m json.tool

echo ""
echo "6. Verificar configuración Nginx:"
grep -A 10 "location /" /etc/nginx/sites-enabled/pucp-orchestrator

echo ""
echo "7. Test con curl verbose para ver qué pasa:"
echo "Probando login a través de nginx con verbose..."
curl -v -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}' 2>&1 | head -20
