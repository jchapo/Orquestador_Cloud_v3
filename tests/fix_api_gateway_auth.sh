#!/bin/bash
# fix_api_gateway_auth.sh

echo "=== Solucionando problema de autorización en API Gateway ==="

# 1. Crear backup del API Gateway actual
cp /opt/pucp-orchestrator/api_gateway.py /opt/pucp-orchestrator/api_gateway_backup_$(date +%s).py

# 2. Crear versión corregida
cat > /opt/pucp-orchestrator/api_gateway_fixed.py << 'EOF'
#!/usr/bin/env python3
"""
PUCP Private Cloud Orchestrator - API Gateway (FIXED)
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import logging
import traceback
import uuid
import time
from datetime import datetime
from functools import wraps
import jwt
import os
import requests
from typing import Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pucp-orchestrator/api-gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class APIGateway:
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        
        self.config = {
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025'),
            'AUTH_SERVICE_URL': os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001'),
            'SLICE_SERVICE_URL': os.getenv('SLICE_SERVICE_URL', 'http://localhost:5002'),
            'TEMPLATE_SERVICE_URL': os.getenv('TEMPLATE_SERVICE_URL', 'http://localhost:5003'),
            'NETWORK_SERVICE_URL': os.getenv('NETWORK_SERVICE_URL', 'http://localhost:5004'),
            'IMAGE_SERVICE_URL': os.getenv('IMAGE_SERVICE_URL', 'http://localhost:5005'),
        }
        
        self.service_routes = {
            '/api/auth': self.config['AUTH_SERVICE_URL'],
            '/api/slices': self.config['SLICE_SERVICE_URL'],
            '/api/templates': self.config['TEMPLATE_SERVICE_URL'],
            '/api/networks': self.config['NETWORK_SERVICE_URL'],
            '/api/images': self.config['IMAGE_SERVICE_URL'],
        }
        
        self.setup_routes()
        self.setup_middleware()
    
    def setup_middleware(self):
        @self.app.before_request
        def before_request():
            g.request_id = str(uuid.uuid4())
            g.start_time = time.time()
            logger.info(f"[{g.request_id}] {request.method} {request.path} from {request.remote_addr}")
            
        @self.app.after_request
        def after_request(response):
            duration = time.time() - g.start_time
            logger.info(f"[{g.request_id}] Response: {response.status_code} in {duration:.3f}s")
            response.headers['X-Request-ID'] = g.request_id
            return response
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload = jwt.decode(token, self.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def require_auth(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            user_info = self.validate_token(token)
            if not user_info:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            g.user = user_info
            return f(*args, **kwargs)
        return decorated_function
    
    def proxy_request(self, service_url: str, path: str):
        """Proxy request con autorización corregida"""
        try:
            # Preparar URL
            if path.startswith('/api/'):
                # Quitar el prefijo /api/ para el microservicio
                clean_path = path[4:]  # Quita '/api'
            else:
                clean_path = path
                
            target_url = f"{service_url}{clean_path}"
            
            # Preparar headers base
            headers = {
                'Content-Type': 'application/json',
                'X-Request-ID': g.request_id if hasattr(g, 'request_id') else str(uuid.uuid4())
            }
            
            # CRÍTICO: Pasar header Authorization original
            auth_header = request.headers.get('Authorization')
            if auth_header:
                headers['Authorization'] = auth_header
                logger.info(f"Forwarding Authorization header: {auth_header[:20]}...")
            
            # Agregar contexto de usuario si está autenticado
            if hasattr(g, 'user'):
                headers['X-User-ID'] = str(g.user.get('user_id', ''))
                headers['X-User-Role'] = g.user.get('role', 'user')
            
            logger.info(f"Proxying {request.method} to {target_url}")
            
            timeout = 30
            
            if request.method == 'GET':
                response = requests.get(
                    target_url, 
                    params=request.args, 
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'POST':
                json_data = request.get_json() if request.is_json else None
                response = requests.post(
                    target_url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'PUT':
                json_data = request.get_json() if request.is_json else None
                response = requests.put(
                    target_url,
                    json=json_data,
                    headers=headers,
                    timeout=timeout
                )
            elif request.method == 'DELETE':
                response = requests.delete(
                    target_url,
                    headers=headers,
                    timeout=timeout
                )
            else:
                return jsonify({'error': 'Method not allowed'}), 405
            
            logger.info(f"Response status: {response.status_code}")
            
            try:
                return response.json(), response.status_code
            except ValueError:
                logger.error(f"Non-JSON response: {response.text}")
                return jsonify({
                    'error': 'Service returned invalid response',
                    'status_code': response.status_code,
                    'response': response.text[:200]
                }), 502
            
        except requests.exceptions.ConnectionError:
            logger.error(f"Service unavailable: {service_url}")
            return jsonify({'error': f'Service unavailable: {service_url}'}), 503
        except requests.exceptions.Timeout:
            logger.error(f"Service timeout: {service_url}")
            return jsonify({'error': 'Service timeout'}), 504
        except Exception as e:
            logger.error(f"Proxy error: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    
    def setup_routes(self):
        @self.app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'services': list(self.service_routes.keys())
            })
        
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            logger.info("Login request received through API Gateway")
            return self.proxy_request(self.config['AUTH_SERVICE_URL'], '/login')
        
        @self.app.route('/api/auth/register', methods=['POST'])
        def register():
            logger.info("Register request received through API Gateway")
            return self.proxy_request(self.config['AUTH_SERVICE_URL'], '/register')
        
        # Protected endpoints (SIN require_auth - deja que los microservicios validen)
        @self.app.route('/api/slices', methods=['GET', 'POST'])
        def slices():
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/slices/<slice_id>', methods=['GET', 'PUT', 'DELETE'])
        def slice_detail(slice_id):
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/slices/<slice_id>/deploy', methods=['POST'])
        def deploy_slice(slice_id):
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/templates', methods=['GET', 'POST'])
        def templates():
            return self.proxy_request(self.config['TEMPLATE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/networks', methods=['GET', 'POST'])
        def networks():
            return self.proxy_request(self.config['NETWORK_SERVICE_URL'], request.path)
        
        @self.app.route('/api/images', methods=['GET', 'POST'])
        def images():
            return self.proxy_request(self.config['IMAGE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/resources', methods=['GET'])
        def resources():
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], '/api/resources')
        
        # Error handlers
        @self.app.errorhandler(400)
        def bad_request(error):
            return jsonify({'error': 'Bad request'}), 400
        
        @self.app.errorhandler(401)
        def unauthorized(error):
            return jsonify({'error': 'Unauthorized'}), 401
        
        @self.app.errorhandler(403)
        def forbidden(error):
            return jsonify({'error': 'Forbidden'}), 403
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({'error': 'Not found'}), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal error: {str(error)}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        logger.info(f"Starting PUCP Cloud Orchestrator API Gateway on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    os.makedirs('/var/log/pucp-orchestrator', exist_ok=True)
    gateway = APIGateway()
    gateway.run(debug=True)
EOF

# 3. Reemplazar API Gateway
echo "Reemplazando API Gateway..."
cp /opt/pucp-orchestrator/api_gateway_fixed.py /opt/pucp-orchestrator/api_gateway.py

# 4. Reiniciar API Gateway
echo "Reiniciando API Gateway..."
sudo pkill -f "python.*api_gateway"
sleep 3

cd /opt/pucp-orchestrator
source venv/bin/activate
python3 api_gateway.py &
GATEWAY_PID=$!

echo "API Gateway corregido iniciado con PID: $GATEWAY_PID"

# 5. Esperar y probar
echo "Esperando que el servicio esté listo..."
sleep 5

echo "Probando el fix..."
# Test de login para obtener token
echo "1. Obteniendo token..."
response=$(curl -s -X POST http://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}')

echo "$response" | python3 -m json.tool

# Extraer token
TOKEN=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    echo ""
    echo "2. Probando endpoint protegido con token..."
    curl -s -X GET http://localhost/api/slices \
      -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
    
    echo ""
    echo "3. Estado del test:"
    if curl -s -X GET http://localhost/api/slices -H "Authorization: Bearer $TOKEN" | grep -q '\['; then
        echo "✓ Autorización funcionando correctamente"
    else
        echo "✗ Autorización aún tiene problemas"
    fi
else
    echo "✗ No se pudo obtener token"
fi

echo ""
echo "Para matar el proceso: kill $GATEWAY_PID"
