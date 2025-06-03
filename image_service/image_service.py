# image_service/image_service.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import os
import uuid
from functools import wraps
import jwt

app = Flask(__name__)
CORS(app)

# Configuración
app.config['DATABASE'] = 'image_service.db'
app.config['UPLOAD_FOLDER'] = '/var/lib/pucp-orchestrator/images'
app.config['ALLOWED_EXTENSIONS'] = {'qcow2', 'vmdk', 'img'}

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS images (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                file_name TEXT NOT NULL,
                file_size INTEGER,
                infrastructure TEXT NOT NULL,
                is_public BOOLEAN DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'uploading',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def token_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, 'pucp-cloud-secret-2025', algorithms=['HS256'])
            g.current_user = payload
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/images', methods=['GET'])
@token_required
def list_images():
    db = get_db()
    images = db.execute('''
        SELECT id, name, description, infrastructure, is_public 
        FROM images 
        WHERE user_id = ? OR is_public = 1
        ORDER BY created_at DESC
    ''', (g.current_user['username'],)).fetchall()
    
    return jsonify([dict(image) for image in images])

@app.route('/api/images', methods=['POST'])
@token_required
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    data = request.form
    required_fields = ['name', 'infrastructure']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    image_id = str(uuid.uuid4())
    file_extension = file.filename.rsplit('.', 1)[1].lower()
    new_filename = f"{image_id}.{file_extension}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
    
    # Crear directorio si no existe
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    try:
        file.save(save_path)
        file_size = os.path.getsize(save_path)
        
        db = get_db()
        db.execute('''
            INSERT INTO images (
                id, user_id, name, description, 
                file_name, file_size, infrastructure, is_public
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            image_id,
            g.current_user['username'],
            data['name'],
            data.get('description'),
            new_filename,
            file_size,
            data['infrastructure'],
            data.get('is_public', False)
        ))
        db.commit()
        
    except Exception as e:
        if os.path.exists(save_path):
            os.remove(save_path)
        return jsonify({'error': str(e)}), 500
    
    return jsonify({
        'id': image_id,
        'message': 'Image uploaded successfully',
        'status': 'processing'
    }), 201

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'image'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5005)
