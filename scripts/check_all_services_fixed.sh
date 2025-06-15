#!/bin/bash
# scripts/check_all_services_fixed.sh

set -e

echo "🔍 PUCP Cloud Orchestrator - Verificación de Servicios"
echo "======================================================"
echo ""
echo "Timestamp: $(date)"
echo ""

# Variables
FAILED_CHECKS=0
TOTAL_CHECKS=0

# Función para logging
check_result() {
    local status=$1
    local message=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ "$status" = "OK" ]; then
        echo "[OK] $message"
    elif [ "$status" = "WARN" ]; then
        echo "[WARN] $message"
    else
        echo "[ERROR] $message"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Test de servicios systemd
echo "=== Servicios Systemd ==="
services=("pucp-api-gateway" "pucp-auth-service" "pucp-slice-service" "pucp-template-service" "pucp-network-service" "pucp-image-service" "nginx")

for service in "${services[@]}"; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        pid=$(systemctl show "$service" --property=MainPID --value)
        started=$(systemctl show "$service" --property=ActiveEnterTimestamp --value)
        check_result "OK" "$service: active (PID: $pid)"
    else
        status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
        check_result "ERROR" "$service: $status"
        echo "         Last logs:"
        systemctl status "$service" --no-pager -l | tail -3 | sed 's/^/              /'
    fi
done

echo ""

# Test de puertos
echo "=== Puertos de Red ==="
ports=(
    "80:HTTP (Nginx)"
    "5000:API Gateway" 
    "5001:Auth Service"
    "5002:Slice Service"
    "5003:Template Service"
    "5004:Network Service"
    "5005:Image Service"
)

for port_info in "${ports[@]}"; do
    port=$(echo "$port_info" | cut -d: -f1)
    desc=$(echo "$port_info" | cut -d: -f2)
    
    if ss -tlnp | grep -q ":$port "; then
        pid_info=$(ss -tlnp | grep ":$port " | awk '{print $6}' | cut -d'"' -f2 | head -1)
        check_result "OK" "Puerto $port ($desc): Activo - $pid_info"
    else
        check_result "ERROR" "Puerto $port ($desc): No está escuchando"
    fi
done

echo ""

# Test de endpoints HTTP
echo "=== Endpoints HTTP ==="
endpoints=(
    "http://localhost/health:API Gateway Health"
    "http://localhost:5001/health:Auth Service Health"
    "http://localhost:5002/health:Slice Service Health"  
    "http://localhost:5003/health:Template Service Health"
    "http://localhost:5004/health:Network Service Health"
    "http://localhost:5005/health:Image Service Health"
)

for endpoint_info in "${endpoints[@]}"; do
    url=$(echo "$endpoint_info" | cut -d: -f1)
    desc=$(echo "$endpoint_info" | cut -d: -f2-)
    
    if timeout 5 curl -s "$url" >/dev/null 2>&1; then
        check_result "OK" "$desc: Respondiendo"
    else
        check_result "ERROR" "$desc: No responde"
    fi
done

echo ""

# Resumen final
echo "=== RESUMEN FINAL ==="
echo "Checks passed: $((TOTAL_CHECKS - FAILED_CHECKS))/$TOTAL_CHECKS"

if [ $FAILED_CHECKS -eq 0 ]; then
    echo "[OK] ✅ TODOS LOS SERVICIOS FUNCIONAN CORRECTAMENTE"
elif [ $FAILED_CHECKS -le 2 ]; then
    echo "[WARN] ⚠️ ALGUNOS SERVICIOS TIENEN PROBLEMAS MENORES"
else
    echo "[ERROR] ❌ VARIOS SERVICIOS TIENEN PROBLEMAS"
    echo "   🚨 Revisar configuración antes de usar en producción"
fi

echo ""
echo "💡 Para más detalles:"
echo "   - Logs: sudo journalctl -u pucp-* --since '10 minutes ago'"
echo "   - Procesos: ps aux | grep python"
echo "   - Health check: curl http://localhost/health"
