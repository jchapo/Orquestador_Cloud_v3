#!/bin/bash
# PUCP Cloud Orchestrator - Complete API Test Script

# Configuración
API_BASE="http://localhost/api"
DIRECT_AUTH_PORT="http://localhost:5001"
GATEWAY_PORT="http://localhost:5000"
TOKEN=""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Función para verificar respuesta HTTP
check_response() {
    local expected_code=$1
    local actual_code=$2
    local test_name=$3
    
    if [ "$actual_code" == "$expected_code" ]; then
        log_info "✓ $test_name (HTTP $actual_code)"
        return 0
    else
        log_error "✗ $test_name - Expected: $expected_code, Got: $actual_code"
        return 1
    fi
}

# Función para hacer peticiones con manejo de errores
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local auth_token=$4
    
    if [ -n "$auth_token" ]; then
        if [ -n "$data" ]; then
            response=$(curl -s -w "%{http_code}" -X "$method" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $auth_token" \
                -d "$data" \
                -o temp_response.json \
                "$url")
        else
            response=$(curl -s -w "%{http_code}" -X "$method" \
                -H "Authorization: Bearer $auth_token" \
                -o temp_response.json \
                "$url")
        fi
    else
        if [ -n "$data" ]; then
            response=$(curl -s -w "%{http_code}" -X "$method" \
                -H "Content-Type: application/json" \
                -d "$data" \
                -o temp_response.json \
                "$url")
        else
            response=$(curl -s -w "%{http_code}" -X "$method" \
                -o temp_response.json \
                "$url")
        fi
    fi
    
    echo "$response"
}

echo -e "${BLUE}=== PUCP Cloud Orchestrator API Tests ===${NC}"
echo "Timestamp: $(date)"
echo ""

# Test 1: Health Check
log_test "1. Testing Health Endpoint"
response=$(make_request "GET" "http://localhost/health")
http_code="${response: -3}"

if check_response "200" "$http_code" "Health check"; then
    echo "Response:"
    cat temp_response.json | python3 -m json.tool 2>/dev/null || cat temp_response.json
else
    log_error "Health endpoint failed. Checking individual services..."
    
    # Verificar servicios individuales
    log_test "Checking API Gateway directly..."
    gateway_response=$(curl -s -w "%{http_code}" -o temp_gateway.json "$GATEWAY_PORT/health")
    gateway_code="${gateway_response: -3}"
    check_response "200" "$gateway_code" "API Gateway direct"
    
    log_test "Checking Auth Service directly..."
    auth_response=$(curl -s -w "%{http_code}" -o temp_auth.json "$DIRECT_AUTH_PORT/health")
    auth_code="${auth_response: -3}"
    check_response "200" "$auth_code" "Auth Service direct"
fi

echo ""

# Test 2: Service Discovery
log_test "2. Testing Individual Services"

services=("auth:5001" "slice:5002" "template:5003" "network:5004" "image:5005")
for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    url="http://localhost:$port/health"
    
    response=$(curl -s -w "%{http_code}" -o temp_service.json "$url")
    http_code="${response: -3}"
    
    if check_response "200" "$http_code" "$name service"; then
        echo "  $name service OK"
    else
        log_error "  $name service failed (port $port)"
    fi
done

echo ""

# Test 3: Authentication Flow
log_test "3. Testing Authentication Flow"

# Registro de usuario
log_test "3.1 User Registration"
register_data='{
    "username": "testuser_'$(date +%s)'",
    "password": "testpass123",
    "email": "test'$(date +%s)'@pucp.edu.pe",
    "role": "student"
}'

response=$(make_request "POST" "${API_BASE}/auth/register" "$register_data")
http_code="${response: -3}"

if check_response "201" "$http_code" "User registration"; then
    echo "Registration successful"
    cat temp_response.json | python3 -m json.tool 2>/dev/null
else
    log_warn "Registration failed, might be user already exists"
fi

echo ""

# Login de usuario
log_test "3.2 User Login"
login_data='{
    "username": "testuser",
    "password": "testpass123"
}'

response=$(make_request "POST" "${API_BASE}/auth/login" "$login_data")
http_code="${response: -3}"

if check_response "200" "$http_code" "User login"; then
    # Extraer token
    TOKEN=$(cat temp_response.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))" 2>/dev/null)
    
    if [ -n "$TOKEN" ]; then
        log_info "✓ Login successful, token obtained"
        echo "Token: ${TOKEN:0:50}..."
    else
        log_error "✗ Token not found in response"
        echo "Response:"
        cat temp_response.json
    fi
else
    log_error "Login failed"
    echo "Response:"
    cat temp_response.json
fi

echo ""

# Test 4: Protected Endpoints (solo si tenemos token)
if [ -n "$TOKEN" ]; then
    log_test "4. Testing Protected Endpoints"
    
    # Test slices endpoint
    log_test "4.1 Slices endpoint"
    response=$(make_request "GET" "${API_BASE}/slices" "" "$TOKEN")
    http_code="${response: -3}"
    
    if check_response "200" "$http_code" "List slices"; then
        echo "Slices response:"
        cat temp_response.json | python3 -m json.tool 2>/dev/null
    fi
    
    echo ""
    
    # Test templates endpoint
    log_test "4.2 Templates endpoint"
    response=$(make_request "GET" "${API_BASE}/templates" "" "$TOKEN")
    http_code="${response: -3}"
    
    if check_response "200" "$http_code" "List templates"; then
        echo "Templates response:"
        cat temp_response.json | python3 -m json.tool 2>/dev/null
    fi
    
    echo ""
    
    # Test resources endpoint
    log_test "4.3 Resources endpoint"
    response=$(make_request "GET" "${API_BASE}/resources" "" "$TOKEN")
    http_code="${response: -3}"
    
    if check_response "200" "$http_code" "Get resources"; then
        echo "Resources response:"
        cat temp_response.json | python3 -m json.tool 2>/dev/null
    fi
    
    echo ""
    
    # Test networks endpoint
    log_test "4.4 Networks endpoint"
    response=$(make_request "GET" "${API_BASE}/networks" "" "$TOKEN")
    http_code="${response: -3}"
    
    if check_response "200" "$http_code" "List networks"; then
        echo "Networks response:"
        cat temp_response.json | python3 -m json.tool 2>/dev/null
    fi
    
    echo ""
else
    log_error "No token available, skipping protected endpoint tests"
fi

# Test 5: Authorization (acceso no autorizado)
log_test "5. Testing Unauthorized Access"
response=$(make_request "GET" "${API_BASE}/slices")
http_code="${response: -3}"

if check_response "401" "$http_code" "Unauthorized access blocked"; then
    log_info "✓ Authorization working correctly"
else
    log_error "✗ Authorization not working properly"
fi

echo ""

# Test 6: Create Slice (ejemplo completo)
if [ -n "$TOKEN" ]; then
    log_test "6. Testing Slice Creation"
    
    slice_data='{
        "name": "test-slice-'$(date +%s)'",
        "description": "Test slice created by automated test",
        "infrastructure": "linux",
        "nodes": [
            {
                "name": "vm1",
                "image": "ubuntu-20.04",
                "flavor": "small"
            },
            {
                "name": "vm2", 
                "image": "ubuntu-20.04",
                "flavor": "small"
            }
        ],
        "networks": [
            {
                "name": "test-network",
                "cidr": "192.168.100.0/24"
            }
        ]
    }'
    
    response=$(make_request "POST" "${API_BASE}/slices" "$slice_data" "$TOKEN")
    http_code="${response: -3}"
    
    if check_response "201" "$http_code" "Create slice"; then
        log_info "✓ Slice created successfully"
        echo "Response:"
        cat temp_response.json | python3 -m json.tool 2>/dev/null
    else
        log_error "✗ Slice creation failed"
        echo "Response:"
        cat temp_response.json
    fi
fi

echo ""

# Test 7: Error Handling
log_test "7. Testing Error Handling"

# Test endpoint inexistente
response=$(make_request "GET" "${API_BASE}/nonexistent")
http_code="${response: -3}"

if check_response "404" "$http_code" "Non-existent endpoint"; then
    log_info "✓ 404 errors handled correctly"
fi

echo ""

# Resumen de resultados
echo -e "${BLUE}=== Test Summary ===${NC}"
echo "Timestamp: $(date)"

# Verificar estado general de servicios
log_test "Service Status Summary:"
ps aux | grep -E "(python.*auth_service|python.*slice_service|python.*template_service|python.*network_service|python.*image_service|python.*api_gateway)" | grep -v grep | while read line; do
    echo "  Running: $(echo $line | awk '{print $11}')"
done

echo ""
log_test "Network Status:"
netstat -tlnp 2>/dev/null | grep -E ":(80|500[0-9])" | while read line; do
    echo "  $line"
done

# Cleanup
rm -f temp_response.json temp_gateway.json temp_auth.json temp_service.json

echo ""
log_info "Test completed!"
