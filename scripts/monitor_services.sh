#!/bin/bash
# PUCP Cloud Orchestrator - Service Monitor

services=("pucp-api-gateway" "pucp-auth-service" "pucp-slice-service" "pucp-template-service" "pucp-network-service" "pucp-image-service")

echo "=== PUCP Cloud Orchestrator Status ==="
echo "$(date)"
echo ""

for service in "${services[@]}"; do
    status=$(systemctl is-active $service)
    if [ "$status" = "active" ]; then
        echo "✓ $service: $status"
    else
        echo "✗ $service: $status"
    fi
done

echo ""
echo "=== Nginx Status ==="
systemctl is-active nginx

echo ""
echo "=== API Health Check ==="
curl -s http://localhost/health | python3 -m json.tool 2>/dev/null || echo "API not responding"

echo ""
echo "=== Resource Usage ==="
ps aux | grep -E "(python|gunicorn|nginx)" | grep -v grep | awk '{print $1, $2, $3, $4, $11}'

echo ""
echo "=== Network Connections ==="
sudo netstat -tlnp | grep -E ":(80|500[0-9])"