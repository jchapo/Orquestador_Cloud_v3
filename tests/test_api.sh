#!/bin/bash
# API Gateway Test Script

API_BASE="http://localhost/api"
TOKEN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== PUCP Cloud Orchestrator API Tests ===${NC}"

# Test health endpoint
echo -e "\n${YELLOW}Testing health endpoint...${NC}"
response=$(curl -s -w "%{http_code}" -o temp_response.json http://localhost/health)
http_code="${response: -3}"

if [ "$http_code" == "200" ]; then
    echo -e "${GREEN}✓ Health check passed${NC}"
    cat temp_response.json | python3 -m json.tool
else
    echo -e "${RED}✗ Health check failed (HTTP $http_code)${NC}"
fi

# Test auth endpoints
echo -e "\n${YELLOW}Testing authentication...${NC}"

# Register test user
echo "Registering test user..."
curl -s -X POST "${API_BASE}/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass123",
    "email": "test@pucp.edu.pe",
    "role": "student"
  }' | python3 -m json.tool

# Login test user
echo -e "\nLogging in test user..."
response=$(curl -s -X POST "${API_BASE}/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass123"
  }')

echo "$response" | python3 -m json.tool

# Extract token (if login successful)
TOKEN=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo -e "${GREEN}✓ Login successful, token obtained${NC}"
    
    # Test protected endpoints
    echo -e "\n${YELLOW}Testing protected endpoints...${NC}"
    
    # Test slices endpoint
    echo "Testing slices endpoint..."
    curl -s -X GET "${API_BASE}/slices" \
      -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
    
    # Test templates endpoint
    echo -e "\nTesting templates endpoint..."
    curl -s -X GET "${API_BASE}/templates" \
      -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
    
    # Test resources endpoint
    echo -e "\nTesting resources endpoint..."
    curl -s -X GET "${API_BASE}/resources" \
      -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
    
else
    echo -e "${RED}✗ Login failed, cannot test protected endpoints${NC}"
fi

# Test unauthorized access
echo -e "\n${YELLOW}Testing unauthorized access...${NC}"
response=$(curl -s -w "%{http_code}" -o temp_response.json "${API_BASE}/slices")
http_code="${response: -3}"

if [ "$http_code" == "401" ]; then
    echo -e "${GREEN}✓ Unauthorized access properly blocked${NC}"
else
    echo -e "${RED}✗ Authorization not working properly (HTTP $http_code)${NC}"
fi

# Clean up
rm -f temp_response.json

echo -e "\n${YELLOW}=== Test completed ===${NC}"
