#!/usr/bin/env python3
"""
PUCP Private Cloud Orchestrator - API Gateway (FIXED)
Main entry point for all client requests to the cloud orchestrator system.
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

# Configure logging
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
        
        # Configuration
        self.config = {
            'JWT_SECRET_KEY': os.getenv('JWT_SECRET_KEY', 'pucp-cloud-secret-2025'),
            'AUTH_SERVICE_URL': os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001'),
            'SLICE_SERVICE_URL': os.getenv('SLICE_SERVICE_URL', 'http://localhost:5002'),
            'TEMPLATE_SERVICE_URL': os.getenv('TEMPLATE_SERVICE_URL', 'http://localhost:5003'),
            'NETWORK_SERVICE_URL': os.getenv('NETWORK_SERVICE_URL', 'http://localhost:5004'),
            'IMAGE_SERVICE_URL': os.getenv('IMAGE_SERVICE_URL', 'http://localhost:5005'),
        }
        
        # Service endpoints mapping
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
        """Setup middleware for logging, CORS, etc."""
        
        @self.app.before_request
        def before_request():
            """Log incoming requests and add request ID"""
            g.request_id = str(uuid.uuid4())
            g.start_time = time.time()
            
            logger.info(f"[{g.request_id}] {request.method} {request.path} from {request.remote_addr}")
            
        @self.app.after_request
        def after_request(response):
            """Log response and timing"""
            duration = time.time() - g.start_time
            logger.info(f"[{g.request_id}] Response: {response.status_code} in {duration:.3f}s")
            response.headers['X-Request-ID'] = g.request_id
            return response
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return user info"""
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
        """Decorator to require authentication"""
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
        """Proxy request to appropriate microservice - FIXED VERSION"""
        try:
            # Preparar URL objetivo
            if path.startswith('/'):
                target_url = f"{service_url}{path}"
            else:
                target_url = f"{service_url}/{path}"
                
            # Preparar headers
            headers = {'Content-Type': 'application/json'}
            
            # Agregar headers de contexto
            headers['X-Request-ID'] = g.request_id if hasattr(g, 'request_id') else str(uuid.uuid4())
            
            # Agregar contexto de usuario si está autenticado
            if hasattr(g, 'user'):
                headers['X-User-ID'] = str(g.user.get('user_id', ''))
                headers['X-User-Role'] = g.user.get('role', 'user')
            
            # Log para debug
            logger.info(f"Proxying {request.method} to {target_url}")
            
            # Realizar request según método
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
                logger.info(f"POST data: {json_data}")
                
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
            
            # Log response para debug
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response content: {response.text[:200]}")
            
            # Intentar parsear como JSON
            try:
                return response.json(), response.status_code
            except ValueError:
                # Si no es JSON válido, devolver error
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
        """Setup API routes"""
        
        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'services': list(self.service_routes.keys())
            })
        
        @self.app.route('/api/auth/login', methods=['POST'])
        def login():
            """Authentication endpoint (doesn't require auth)"""
            logger.info("Login request received through API Gateway")
            return self.proxy_request(self.config['AUTH_SERVICE_URL'], '/login')
        
        @self.app.route('/api/auth/register', methods=['POST'])
        def register():
            """User registration endpoint"""
            logger.info("Register request received through API Gateway")
            return self.proxy_request(self.config['AUTH_SERVICE_URL'], '/register')
        
        # Protected endpoints
        @self.app.route('/api/slices', methods=['GET', 'POST'])
        @self.require_auth
        def slices():
            """Slice management endpoints"""
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/slices/<slice_id>', methods=['GET', 'PUT', 'DELETE'])
        @self.require_auth
        def slice_detail(slice_id):
            """Individual slice operations"""
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/slices/<slice_id>/deploy', methods=['POST'])
        @self.require_auth
        def deploy_slice(slice_id):
            """Deploy a slice"""
            return self.proxy_request(self.config['SLICE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/templates', methods=['GET', 'POST'])
        @self.require_auth
        def templates():
            """Template management"""
            return self.proxy_request(self.config['TEMPLATE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/networks', methods=['GET', 'POST'])
        @self.require_auth
        def networks():
            """Network management"""
            return self.proxy_request(self.config['NETWORK_SERVICE_URL'], request.path)
        
        @self.app.route('/api/images', methods=['GET', 'POST'])
        @self.require_auth
        def images():
            """Image management"""
            return self.proxy_request(self.config['IMAGE_SERVICE_URL'], request.path)
        
        @self.app.route('/api/resources', methods=['GET'])
        @self.require_auth
        def resources():
            """Get system resources status"""
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
        """Run the API Gateway"""
        logger.info(f"Starting PUCP Cloud Orchestrator API Gateway on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    # Create log directory if it doesn't exist
    os.makedirs('/var/log/pucp-orchestrator', exist_ok=True)
    
    # Initialize and run the API Gateway
    gateway = APIGateway()
    gateway.run(debug=True)
