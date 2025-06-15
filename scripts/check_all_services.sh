#!/bin/bash
"""
PUCP Cloud Orchestrator - Verificación completa de servicios
"""

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Función para logging con colores
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_title() {
    echo -e "${PURPLE}=== $1 ===${NC}"
}

# Verificar servicios systemd
check_systemd_services() {
    log_title "Servicios Systemd"
    
    services=(
        "pucp-api-gateway:API Gateway"
        "pucp-auth-service:Auth Service"
        "pucp-slice-service:Slice Service"
        "pucp-template-service:Template Service"
        "pucp-network-service:Network Service"
        "pucp-image-service:Image Service"
        "nginx:Nginx Proxy"
    )
    
    all_ok=true
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r service_name description <<< "$service_info"
        
        if systemctl is-active --quiet "$service_name"; then
            status=$(systemctl show -p ActiveState --value "$service_name")
            log_success "$description ($service_name): $status"
            
            # Mostrar info adicional si está activo
            if [ "$status" = "active" ]; then
                pid=$(systemctl show -p MainPID --value "$service_name")
                uptime=$(systemctl show -p ActiveEnterTimestamp --value "$service_name")
                echo "         PID: $pid, Started: $uptime"
            fi
        else
            status=$(systemctl show -p ActiveState --value "$service_name")
            log_error "$description ($service_name): $status"
            all_ok=false
            
            # Mostrar últimos logs si hay error
            echo "         Last logs:"
            systemctl status "$service_name" --no-pager -l | tail -3 | sed 's/^/         /'
        fi
    done
    
    return $all_ok
}

# Verificar puertos de red
check_network_ports() {
    log_title "Puertos de Red"
    
    ports=(
        "80:HTTP (Nginx)"
        "443:HTTPS (Nginx)"
        "5000:API Gateway"
        "5001:Auth Service"
        "5002:Slice Service"
        "5003:Template Service"
        "5004:Network Service"
        "5005:Image Service"
    )
    
    all_ok=true
    
    for port_info in "${ports[@]}"; do
        IFS=':' read -r port description <<< "$port_info"
        
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            process=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | head -1)
            log_success "Puerto $port ($description): Activo - $process"
        else
            log_error "Puerto $port ($description): No está escuchando"
            all_ok=false
        fi
    done
    
    return $all_ok
}

# Verificar conectividad HTTP
check_http_endpoints() {
    log_title "Endpoints HTTP"
    
    endpoints=(
        "http://localhost/health:API Gateway Health"
        "http://localhost:5001/health:Auth Service Health"
        "http://localhost:5002/health:Slice Service Health"
        "http://localhost:5003/health:Template Service Health"
        "http://localhost:5004/health:Network Service Health"
        "http://localhost:5005/health:Image Service Health"
    )
    
    all_ok=true
    
    for endpoint_info in "${endpoints[@]}"; do
        IFS=':' read -r url description <<< "$endpoint_info"
        
        if response=$(curl -s -w "%{http_code}" -o /tmp/response.json --max-time 5 "$url" 2>/dev/null); then
            http_code="${response: -3}"
            if [ "$http_code" = "200" ]; then
                service_status=$(cat /tmp/response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
                log_success "$description: HTTP $http_code - Status: $service_status"
            else
                log_warning "$description: HTTP $http_code"
                all_ok=false
            fi
        else
            log_error "$description: No responde"
            all_ok=false
        fi
    done
    
    rm -f /tmp/response.json
    return $all_ok
}

# Verificar autenticación
check_authentication() {
    log_title "Test de Autenticación"
    
    # Test de login
    log_info "Probando login con usuario de prueba..."
    
    login_response=$(curl -s -X POST http://localhost/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser", "password": "testpass123"}' \
        2>/dev/null)
    
    if echo "$login_response" | grep -q "token"; then
        log_success "Autenticación: Login exitoso"
        
        # Extraer token para pruebas adicionales
        token=$(echo "$login_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))" 2>/dev/null)
        
        if [ -n "$token" ]; then
            # Test de endpoint protegido
            protected_response=$(curl -s -H "Authorization: Bearer $token" \
                http://localhost/api/slices 2>/dev/null)
            
            if echo "$protected_response" | grep -q -E '(\[|\{)'; then
                log_success "Autorización: Endpoint protegido accesible"
                return 0
            else
                log_warning "Autorización: Problema con endpoint protegido"
                return 1
            fi
        fi
    else
        log_error "Autenticación: Login falló"
        echo "Response: $login_response"
        return 1
    fi
}

# Verificar bases de datos
check_databases() {
    log_title "Bases de Datos SQLite"
    
    databases=(
        "/opt/pucp-orchestrator/auth_service/auth_service.db:Auth Database"
        "/opt/pucp-orchestrator/slice_service/slice_service.db:Slice Database"
        "/opt/pucp-orchestrator/template_service/template_service.db:Template Database"
        "/opt/pucp-orchestrador/network_service/network_service.db:Network Database"
        "/opt/pucp-orchestrator/image_service/image_service.db:Image Database"
    )
    
    all_ok=true
    
    for db_info in "${databases[@]}"; do
        IFS=':' read -r db_path description <<< "$db_info"
        
        if [ -f "$db_path" ]; then
            size=$(du -h "$db_path" | cut -f1)
            log_success "$description: Existe ($size)"
            
            # Verificar que es una DB válida
            if sqlite3 "$db_path" "SELECT COUNT(*) FROM sqlite_master;" >/dev/null 2>&1; then
                tables=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
                echo "         Tablas: $tables"
            else
                log_warning "$description: DB corrupta o inaccesible"
                all_ok=false
            fi
        else
            log_error "$description: No existe ($db_path)"
            all_ok=false
        fi
    done
    
    return $all_ok
}

# Verificar logs
check_logs() {
    log_title "Archivos de Log"
    
    log_files=(
        "/var/log/pucp-orchestrator/api-gateway.log:API Gateway Logs"
        "/var/log/pucp-orchestrator/slice-service.log:Slice Service Logs"
        "/var/log/nginx/access.log:Nginx Access Logs"
        "/var/log/nginx/error.log:Nginx Error Logs"
    )
    
    for log_info in "${log_files[@]}"; do
        IFS=':' read -r log_path description <<< "$log_info"
        
        if [ -f "$log_path" ]; then
            size=$(du -h "$log_path" | cut -f1)
            lines=$(wc -l < "$log_path")
            log_success "$description: $size ($lines líneas)"
            
            # Mostrar últimas líneas si hay errores recientes
            if grep -q -i "error\|exception\|failed" "$log_path" | tail -10 >/dev/null 2>&1; then
                echo "         Errores recientes encontrados"
            fi
        else
            log_warning "$description: No existe"
        fi
    done
}

# Verificar recursos del sistema
check_system_resources() {
    log_title "Recursos del Sistema"
    
    # CPU
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    log_info "CPU Usage: $cpu_usage"
    
    # Memoria
    memory_info=$(free -h | grep "^Mem:")
    total_mem=$(echo $memory_info | awk '{print $2}')
    used_mem=$(echo $memory_info | awk '{print $3}')
    log_info "Memory: $used_mem / $total_mem"
    
    # Disco
    disk_info=$(df -h / | tail -1)
    disk_used=$(echo $disk_info | awk '{print $3}')
    disk_total=$(echo $disk_info | awk '{print $2}')
    disk_percent=$(echo $disk_info | awk '{print $5}')
    log_info "Disk: $disk_used / $disk_total ($disk_percent)"
    
    # Procesos Python
    python_processes=$(ps aux | grep -E "(python|gunicorn)" | grep -v grep | wc -l)
    log_info "Python processes: $python_processes"
}

# Verificar cluster Linux
check_linux_cluster() {
    log_title "Cluster Linux"
    
    if [ -f "/opt/pucp-orchestrator/cluster_config.json" ]; then
        log_success "Configuración del cluster encontrada"
        
        # Verificar conectividad a servidores
        servers=$(python3 -c "
import json
try:
    with open('/opt/pucp-orchestrator/cluster_config.json') as f:
        config = json.load(f)
    for name in config.get('servers', {}):
        print(name)
except:
    pass
" 2>/dev/null)
        
        if [ -n "$servers" ]; then
            log_info "Verificando conectividad a servidores del cluster..."
            for server in $servers; do
                if ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no "$server" "hostname" >/dev/null 2>&1; then
                    log_success "  $server: Conectado"
                else
                    log_warning "  $server: No accesible"
                fi
            done
        fi
    else
        log_warning "Configuración del cluster no encontrada"
    fi
}

# Función principal
main() {
    echo -e "${CYAN}"
    echo "🔍 PUCP Cloud Orchestrator - Verificación de Servicios"
    echo "======================================================"
    echo -e "${NC}"
    echo "Timestamp: $(date)"
    echo ""
    
    # Contadores de resultados
    total_checks=0
    passed_checks=0
    
    # Ejecutar todas las verificaciones
    checks=(
        "check_systemd_services:Servicios Systemd"
        "check_network_ports:Puertos de Red"
        "check_http_endpoints:Endpoints HTTP"
        "check_authentication:Autenticación"
        "check_databases:Bases de Datos"
        "check_logs:Archivos de Log"
        "check_system_resources:Recursos del Sistema"
        "check_linux_cluster:Cluster Linux"
    )
    
    for check_info in "${checks[@]}"; do
        IFS=':' read -r check_func description <<< "$check_info"
        
        echo ""
        if $check_func; then
            passed_checks=$((passed_checks + 1))
        fi
        total_checks=$((total_checks + 1))
    done
    
    # Resumen final
    echo ""
    log_title "RESUMEN FINAL"
    echo "Checks passed: $passed_checks/$total_checks"
    
    if [ $passed_checks -eq $total_checks ]; then
        log_success "🎉 TODOS LOS SERVICIOS ESTÁN FUNCIONANDO CORRECTAMENTE"
        echo -e "${GREEN}   ✅ Sistema listo para producción${NC}"
    elif [ $passed_checks -ge $((total_checks * 3 / 4)) ]; then
        log_warning "⚠️  LA MAYORÍA DE SERVICIOS ESTÁN FUNCIONANDO"
        echo -e "${YELLOW}   ⚠️  Algunos componentes necesitan atención${NC}"
    else
        log_error "❌ VARIOS SERVICIOS TIENEN PROBLEMAS"
        echo -e "${RED}   🚨 Revisar configuración antes de usar en producción${NC}"
    fi
    
    echo ""
    echo "💡 Para más detalles:"
    echo "   - Logs: sudo journalctl -u pucp-* --since '1 hour ago'"
    echo "   - Procesos: ps aux | grep python"
    echo "   - Red: sudo netstat -tlnp | grep :50"
    echo "   - Health check manual: curl http://localhost/health"
}

# Verificar que se ejecuta como usuario correcto
if [ "$EUID" -eq 0 ]; then
    log_warning "Ejecutándose como root - algunos checks pueden fallar"
fi

main "$@"
