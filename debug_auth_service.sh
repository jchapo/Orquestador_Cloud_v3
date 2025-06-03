#!/bin/bash
# Script para diagnosticar problemas del Auth Service

echo "=== Diagnóstico Auth Service ==="

# 1. Verificar estado del servicio
echo "1. Estado del servicio auth:"
systemctl status pucp-auth-service --no-pager

echo ""
echo "2. Verificar si el puerto está ocupado:"
sudo netstat -tlnp | grep :5001

echo ""
echo "3. Verificar logs del auth service:"
sudo journalctl -u pucp-auth-service --lines=20 --no-pager

echo ""
echo "4. Verificar si el auth service responde directamente:"
curl -s http://localhost:5001/health || echo "Auth service no responde"

echo ""
echo "5. Verificar base de datos del auth service:"
if [ -f "/opt/pucp-orchestrator/auth_service/auth_service.db" ]; then
    echo "✓ Base de datos existe"
    sqlite3 /opt/pucp-orchestrator/auth_service/auth_service.db "SELECT name FROM sqlite_master WHERE type='table';" || echo "Error leyendo DB"
else
    echo "✗ Base de datos no encontrada"
fi

echo ""
echo "6. Verificar configuración:"
if [ -f "/opt/pucp-orchestrator/.env" ]; then
    echo "✓ Archivo .env existe"
    grep -E "(AUTH_SERVICE_URL|JWT_SECRET)" /opt/pucp-orchestrator/.env
else
    echo "✗ Archivo .env no encontrado"
fi

echo ""
echo "7. Verificar archivo auth_service.py:"
if [ -f "/opt/pucp-orchestrator/auth_service/auth_service.py" ]; then
    echo "✓ Archivo auth_service.py existe"
    head -5 /opt/pucp-orchestrator/auth_service/auth_service.py
else
    echo "✗ Archivo auth_service.py no encontrado"
fi

echo ""
echo "8. Verificar procesos Python:"
ps aux | grep -E "(auth_service|python)" | grep -v grep
