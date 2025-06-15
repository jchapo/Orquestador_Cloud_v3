#!/bin/bash
"""
Check rápido del estado de PUCP Orchestrator
"""

echo "🚀 PUCP Orchestrator - Estado Rápido"
echo "===================================="

# Servicios principales
echo "📋 Servicios:"
for service in pucp-api-gateway pucp-auth-service pucp-slice-service pucp-template-service pucp-network-service pucp-image-service nginx; do
    if systemctl is-active --quiet $service; then
        echo "  ✅ $service"
    else
        echo "  ❌ $service"
    fi
done

echo ""
echo "🌐 Puertos:"
for port in 80 5001 5002 5003 5004 5005; do
    if netstat -tln 2>/dev/null | grep -q ":$port "; then
        echo "  ✅ :$port"
    else
        echo "  ❌ :$port"
    fi
done

echo ""
echo "🔍 Health Checks:"
for url in "http://localhost/health" "http://localhost:5001/health"; do
    if curl -s --max-time 3 "$url" | grep -q "healthy"; then
        echo "  ✅ $url"
    else
        echo "  ❌ $url"
    fi
done

echo ""
echo "💾 Procesos Python:"
ps aux | grep -E "(python.*pucp|gunicorn)" | grep -v grep | wc -l | xargs echo "  Procesos activos:"
