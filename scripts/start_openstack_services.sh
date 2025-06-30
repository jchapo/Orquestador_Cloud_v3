#!/bin/bash

echo "🚀 Iniciando servicios OpenStack en headnode..."

ssh -o ConnectTimeout=10 ubuntu@10.20.12.187 -p 5821 << 'REMOTE_SCRIPT'
# Conectar al headnode y arrancar servicios

echo "=== Iniciando servicios básicos ==="
sudo systemctl start mariadb
sudo systemctl start rabbitmq-server
sudo systemctl start memcached

echo "=== Iniciando Keystone ==="
sudo systemctl start apache2

echo "=== Iniciando Nova services ==="
sudo systemctl start nova-api
sudo systemctl start nova-conductor  
sudo systemctl start nova-scheduler
sudo systemctl start nova-novncproxy

echo "=== Iniciando Neutron ==="
sudo systemctl start neutron-server

echo "=== Iniciando Glance ==="
sudo systemctl start glance-api

echo "=== Verificando servicios ==="
sleep 5

for service in apache2 nova-api nova-conductor nova-scheduler neutron-server glance-api; do
    if systemctl is-active --quiet $service; then
        echo "✅ $service: STARTED"
    else
        echo "❌ $service: FAILED TO START"
        sudo systemctl status $service --no-pager -l
    fi
done

echo "=== Verificando puertos ==="
netstat -tlnp | grep -E "(5000|8774|9292|9696)"
REMOTE_SCRIPT
