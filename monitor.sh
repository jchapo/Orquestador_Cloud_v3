#!/bin/bash
# PUCP Cloud Orchestrator - Monitoring Script

echo "=== PUCP Cloud Orchestrator Status ==="

# Check API Gateway service
echo "API Gateway Service:"
sudo systemctl is-active pucp-api-gateway
echo ""

# Check Nginx
echo "Nginx Service:"
sudo systemctl is-active nginx
echo ""

# Check if API is responding
echo "API Health Check:"
curl -s http://localhost/health | python3 -m json.tool 2>/dev/null || echo "API not responding"
echo ""

# Show recent logs
echo "Recent API Gateway Logs:"
sudo journalctl -u pucp-api-gateway --lines=10 --no-pager
echo ""

# Show process information
echo "Process Information:"
ps aux | grep -E "(gunicorn|nginx)" | grep -v grep
echo ""

# Show network connections
echo "Network Connections:"
sudo netstat -tlnp | grep -E ":(80|5000)"
