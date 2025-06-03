#!/bin/bash
# PUCP Cloud Orchestrator - Complete Deployment Script
# Despliega todos los microservicios mejorados

set -e  # Salir en caso de error

echo "=== PUCP Cloud Orchestrator - Complete Deployment ==="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
PROJECT_DIR="/opt/pucp-orchestrator"
VENV_DIR="$PROJECT_DIR/venv"
LOG_DIR="/var/log/pucp-orchestrator"
USER=$(whoami)

echo -e "${BLUE}Deployment User: $USER${NC}"
echo -e "${BLUE}Project Directory: $PROJECT_DIR${NC}"

# Función para logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar permisos
if [[ $EUID -eq 0 ]]; then
   log_error "No ejecutar como root. Usar usuario con sudo."
   exit 1
fi

# Crear directorios necesarios
log_info "Creando estructura de directorios..."
sudo mkdir -p $LOG_DIR
sudo chown $USER:$USER $LOG_DIR

mkdir -p $PROJECT_DIR/{auth_service,slice_service,template_service,network_service,image_service,tests}

# Actualizar sistema
log_info "Actualizando sistema..."
sudo apt update && sudo apt upgrade -y

# Instalar dependencias del sistema
log_info "Instalando dependencias del sistema..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    supervisor \
    git \
    curl \
    wget \
    htop \
    net-tools \
    sqlite3 \
    openvswitch-switch \
    openvswitch-common

# Crear entorno virtual
log_info "Creando entorno virtual Python..."
cd $PROJECT_DIR
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv venv
fi

source venv/bin/activate

# Instalar dependencias Python
log_info "Instalando dependencias Python..."
pip install --upgrade pip
pip install \
    flask==2.3.3 \
    flask-cors==4.0.0 \
    pyjwt==2.8.0 \
    requests==2.31.0 \
    gunicorn==21.2.0 \
    python-dotenv==1.0.0 \
    werkzeug==2.3.7 \
    ipaddress

# Crear archivo de configuración principal
log_info "Creando configuración principal..."
cat > $PROJECT_DIR/.env << 'EOF'
# PUCP Cloud Orchestrator Environment Variables
FLASK_ENV=production
JWT_SECRET_KEY=pucp-cloud-secret-2025-change-in-production
TOKEN_EXPIRATION_HOURS=24

# Service URLs
AUTH_SERVICE_URL=http://localhost:5001
SLICE_SERVICE_URL=http://localhost:5002
TEMPLATE_SERVICE_URL=http://localhost:5003
NETWORK_SERVICE_URL=http://localhost:5004
IMAGE_SERVICE_URL=http://localhost:5005

# Infrastructure
LINUX_CLUSTER_SUBNET=10.60.1.0/24
OPENSTACK_CLUSTER_SUBNET=10.60.2.0/24

# Driver URLs
LINUX_DRIVER_URL=http://localhost:6001
OPENSTACK_DRIVER_URL=http://localhost:6002
RESOURCE_MANAGER_URL=http://localhost:6003

# OpenFlow Controller
OPENFLOW_CONTROLLER_URL=http://localhost:6633
OVS_MANAGER_URL=http://localhost:6634
EOF

# Crear servicios systemd para cada microservicio
log_info "Creando servicios systemd..."

# Auth Service
sudo tee /etc/systemd/system/pucp-auth-service.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - Auth Service
After=network.target

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR/auth_service
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python auth_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Slice Service
sudo tee /etc/systemd/system/pucp-slice-service.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - Slice Service
After=network.target pucp-auth-service.service

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR/slice_service
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python slice_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Template Service
sudo tee /etc/systemd/system/pucp-template-service.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - Template Service
After=network.target pucp-auth-service.service

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR/template_service
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python template_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Network Service
sudo tee /etc/systemd/system/pucp-network-service.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - Network Service
After=network.target pucp-auth-service.service

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR/network_service
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python network_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Image Service
sudo tee /etc/systemd/system/pucp-image-service.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - Image Service
After=network.target pucp-auth-service.service

[Service]
Type=exec
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR/image_service
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python image_service.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# API Gateway
sudo tee /etc/systemd/system/pucp-api-gateway.service > /dev/null << EOF
[Unit]
Description=PUCP Cloud Orchestrator - API Gateway
After=network.target pucp-auth-service.service pucp-slice-service.service

[Service]
Type=notify
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/gunicorn --config gunicorn.conf.py wsgi:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Crear configuración nginx mejorada
log_info "Configurando Nginx..."
sudo tee /etc/nginx/sites-available/pucp-orchestrator > /dev/null << 'EOF'
upstream api_gateway {
    server 127.0.0.1:5000;
}

upstream auth_service {
    server 127.0.0.1:5001;
}

upstream slice_service {
    server 127.0.0.1:5002;
}

upstream template_service {
    server 127.0.0.1:5003;
}

upstream network_service {
    server 127.0.0.1:5004;
}

upstream image_service {
    server 127.0.0.1:5005;
}

server {
    listen 80;
    server_name _;

    # Límites de rate limiting
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    # Logs
    access_log /var/log/nginx/pucp-orchestrator-access.log;
    error_log /var/log/nginx/pucp-orchestrator-error.log;

    # Main API Gateway
    location / {
        proxy_pass http://api_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        limit_req zone=api burst=20 nodelay;
    }

    # Authentication endpoints with rate limiting
    location /api/auth/login {
        proxy_pass http://api_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        limit_req zone=auth burst=3 nodelay;
    }

    # Health check (no rate limit)
    location /health {
        proxy_pass http://api_gateway/health;
        access_log off;
    }

    # Direct service access for debugging (remove in production)
    location /debug/auth/ {
        proxy_pass http://auth_service/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /debug/slice/ {
        proxy_pass http://slice_service/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Static files for documentation
    location /docs/ {
        alias /opt/pucp-orchestrator/docs/;
        try_files $uri $uri/ =404;
    }
}
EOF

# Habilitar sitio nginx
sudo ln -sf /etc/nginx/sites-available/pucp-orchestrator /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Crear script de monitoreo
log_info "Creando scripts de monitoreo..."
cat > $PROJECT_DIR/monitor_services.sh << 'EOF'
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
EOF

chmod +x $PROJECT_DIR/monitor_services.sh

# Crear script de backup
cat > $PROJECT_DIR/backup_databases.sh << 'EOF'
#!/bin/bash
# PUCP Cloud Orchestrator - Database Backup

BACKUP_DIR="/opt/pucp-orchestrator/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

echo "Backing up databases..."

# Backup each service database
services=("auth_service" "slice_service" "template_service" "network_service" "image_service")

for service in "${services[@]}"; do
    db_file="/opt/pucp-orchestrator/${service}/${service}.db"
    if [ -f "$db_file" ]; then
        cp "$db_file" "$BACKUP_DIR/${service}_${DATE}.db"
        echo "✓ Backed up $service database"
    else
        echo "⚠ Database not found: $db_file"
    fi
done

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.db" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR"
EOF

chmod +x $PROJECT_DIR/backup_databases.sh

# Crear script de inicialización
cat > $PROJECT_DIR/init_services.sh << 'EOF'
#!/bin/bash
# Initialize all services and create default data

echo "Initializing PUCP Cloud Orchestrator services..."

# Wait for services to start
sleep 10

# Create default admin user
echo "Creating default admin user..."
curl -X POST http://localhost:5001/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123",
    "email": "admin@pucp.edu.pe",
    "role": "admin"
  }' || echo "Admin user may already exist"

# Create test student user
echo "Creating test student user..."
curl -X POST http://localhost:5001/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "estudiante1",
    "password": "estudiante123",
    "email": "estudiante1@pucp.edu.pe",
    "role": "student"
  }' || echo "Student user may already exist"

echo "Service initialization completed!"
EOF

chmod +x $PROJECT_DIR/init_services.sh

# Crear cron job para backups
log_info "Configurando backup automático..."
(crontab -l 2>/dev/null; echo "0 2 * * * $PROJECT_DIR/backup_databases.sh >> /var/log/pucp-orchestrator/backup.log 2>&1") | crontab -

# Configurar logrotate
sudo tee /etc/logrotate.d/pucp-orchestrator > /dev/null << 'EOF'
/var/log/pucp-orchestrator/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 ubuntu ubuntu
    postrotate
        systemctl reload nginx
    endscript
}
EOF

# Configurar firewall básico
log_info "Configurando firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 10.60.0.0/16  # Permitir tráfico interno del proyecto

# Recargar systemd y habilitar servicios
log_info "Habilitando servicios..."
sudo systemctl daemon-reload

# Habilitar todos los servicios
services=("pucp-auth-service" "pucp-slice-service" "pucp-template-service" "pucp-network-service" "pucp-image-service" "pucp-api-gateway")
for service in "${services[@]}"; do
    sudo systemctl enable $service
done

sudo systemctl enable nginx

# Verificar configuración nginx
sudo nginx -t

echo ""
log_info "=== Deployment completado ==="
echo ""
echo -e "${YELLOW}Próximos pasos:${NC}"
echo "1. Copiar los archivos de código Python mejorados a sus respectivos directorios"
echo "2. Iniciar servicios:"
echo "   sudo systemctl start pucp-auth-service"
echo "   sudo systemctl start pucp-slice-service"
echo "   sudo systemctl start pucp-template-service"
echo "   sudo systemctl start pucp-network-service"
echo "   sudo systemctl start pucp-image-service"
echo "   sudo systemctl start pucp-api-gateway"
echo "   sudo systemctl start nginx"
echo ""
echo "3. Inicializar datos por defecto:"
echo "   ./init_services.sh"
echo ""
echo "4. Monitorear servicios:"
echo "   ./monitor_services.sh"
echo ""
echo "5. Testing:"
echo "   cd tests && ./test_api.sh"
echo ""
echo -e "${GREEN}API estará disponible en: http://$(hostname -I | awk '{print $1}')/${NC}"
echo -e "${GREEN}Documentación en: http://$(hostname -I | awk '{print $1}')/docs/${NC}"
