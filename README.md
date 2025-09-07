# Orquestador Cloud v3

![Python](https://img.shields.io/badge/python-v3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

**Orquestador Cloud v3** es una plataforma robusta desarrollada en Python para la orquestación de recursos y servicios en entornos de cómputo distribuido (clúster Linux, OpenStack). La arquitectura basada en microservicios incluye un API Gateway centralizado y servicios especializados para autenticación, gestión de imágenes, networking, plantillas y slices.

<img width="924" height="575" alt="Screenshot from 2025-09-07 01-17-33" src="https://github.com/user-attachments/assets/c3cfbb02-6563-4bf5-b655-0e5f58f0227e" />

## ✨ Características principales

- 🚀 **API Gateway unificado** con endpoints RESTful
- 🔐 **Sistema de autenticación y autorización** robusto
- 🖼️ **Gestión de imágenes** y artefactos
- 🌐 **Administración de red** avanzada
- 📋 **Sistema de plantillas** flexible
- 🍰 **Gestión de slices** para entornos lógicos
- 🖥️ **CLI integrada** para operaciones desde terminal
- ⚡ **Soporte multi-backend** (Linux, OpenStack)
- 🧪 **Suite de pruebas automatizadas**

## 🏗️ Arquitectura

```
┌─────────────────┐
│   API Gateway   │  ← Punto único de entrada
└─────┬───────────┘
      │
      ├── 🔐 Auth Service
      ├── 🖼️ Image Service  
      ├── 🌐 Network Service
      ├── 🍰 Slice Service
      └── 📋 Template Service
```

### Componentes principales

| Componente | Descripción | Archivo principal |
|------------|-------------|-------------------|
| **API Gateway** | Enrutador principal y proxy reverso | `api_gateway.py` |
| **Auth Service** | Autenticación JWT y autorización RBAC | `auth_service/` |
| **Image Service** | Gestión de imágenes y artefactos | `image_service/` |
| **Network Service** | Configuración de redes virtuales | `network_service/` |
| **Slice Service** | Administración de entornos lógicos | `slice_service/` |
| **Template Service** | Motor de plantillas y configuraciones | `template_service/` |

## 📁 Estructura del proyecto

```
Orquestador_Cloud_v3/
├── 🔐 auth_service/          # Servicio de autenticación
├── 🖼️ image_service/         # Gestión de imágenes
├── 🌐 network_service/       # Administración de red
├── 🍰 slice_service/         # Gestión de slices
├── 📋 template_service/      # Motor de plantillas
├── 🖥️ pucp-cli/             # Interfaz de línea de comandos
├── 📚 docs/                 # Documentación adicional
├── 🔧 scripts/              # Scripts de utilidad
├── 🧪 tests/                # Suite de pruebas
├── ⚙️ api_gateway.py        # Gateway principal
├── 🌐 wsgi.py               # Aplicación WSGI
├── 🔧 gunicorn.conf.py      # Configuración del servidor
├── 📦 requirements.txt      # Dependencias Python
├── ⚙️ cluster_config.json   # Configuración base
├── 🐧 linux_cluster_config.json    # Config Linux
├── ☁️ openstack_cluster_config.json # Config OpenStack
├── 🚀 start.sh              # Script de inicio
├── 🔧 init_services.sh      # Inicialización de servicios
└── 📖 API_DOCUMENTATION.md  # Documentación de APIs
```

## 📋 Requisitos del sistema

### Mínimos
- **Python**: 3.10 o superior
- **Sistema operativo**: Linux, macOS, Windows
- **RAM**: 4GB mínimo, 8GB recomendado
- **Almacenamiento**: 2GB de espacio libre

### Dependencias
- `pip` y `venv` para gestión de paquetes
- Acceso de red al entorno objetivo (Linux/OpenStack)
- Variables de entorno configuradas

## 🚀 Instalación

### Método 1: Instalación estándar

```bash
# 1. Clonar el repositorio
git clone https://github.com/jchapo/Orquestador_Cloud_v3.git
cd Orquestador_Cloud_v3

# 2. Crear entorno virtual
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env .env.local
# Editar .env.local con tus credenciales

# 5. Inicializar servicios
./init_services.sh

# 6. Ejecutar el servidor
./start.sh
```

### Método 2: Desarrollo rápido

```bash
# Modo desarrollo con recarga automática
python api_gateway.py --debug

# Modo producción con Gunicorn
gunicorn -c gunicorn.conf.py wsgi:app
```

## ⚙️ Configuración

### Variables de entorno

Crea un archivo `.env.local` basado en `.env`:

```bash
# Configuración de la aplicación
DEBUG=false
PORT=8000
HOST=0.0.0.0

# Base de datos
DATABASE_URL=postgresql://user:pass@localhost/orchestrator

# Credenciales de OpenStack
OS_AUTH_URL=https://your-openstack.example.com:5000/v3
OS_USERNAME=your-username
OS_PASSWORD=your-password
OS_PROJECT_NAME=your-project

# Configuración de clúster Linux
LINUX_SSH_KEY=/path/to/your/ssh/key
LINUX_USERNAME=admin
```

### Archivos de configuración

| Archivo | Propósito | Uso |
|---------|-----------|-----|
| `cluster_config.json` | Configuración base genérica | Plantilla de referencia |
| `linux_cluster_config.json` | Configuración para clúster Linux | Entornos bare-metal |
| `openstack_cluster_config.json` | Configuración para OpenStack | Clouds públicos/privados |

## 🧩 Uso de servicios

### API Gateway

El gateway está disponible en `http://localhost:8000` por defecto.

```bash
# Verificar estado de salud
curl http://localhost:8000/health

# Autenticación
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}'
```

### CLI (pucp-cli)

<img width="924" height="575" alt="Screenshot from 2025-09-07 01-17-56" src="https://github.com/user-attachments/assets/fed3e121-40a1-4685-a14d-730d4c2a868e" />

```bash
# Listar slices disponibles
./pucp-cli/pucp slice list

# Crear una nueva topología
./pucp-cli/pucp topology create --template basic-web

# Gestionar imágenes
./pucp-cli/pucp image list
./pucp-cli/pucp image upload --file myimage.qcow2
```

## 🧪 Pruebas

### Ejecutar todas las pruebas

```bash
# Instalar dependencias de desarrollo
pip install pytest pytest-cov

# Ejecutar suite completa
pytest

# Con cobertura de código
pytest --cov=. --cov-report=html
```

### Pruebas específicas

```bash
# Pruebas de Linux
pytest tests/test_linux_topology.py -v

# Pruebas de OpenStack  
pytest tests/test_openstack_complete.py -v

# Pruebas de integración
pytest tests/integration/ -v
```

## 📖 Documentación de API

La documentación completa de endpoints está disponible en:
- **Archivo**: [`API_DOCUMENTATION.md`](./API_DOCUMENTATION.md)
- **Swagger UI**: `http://localhost:8000/docs` (cuando el servidor esté ejecutándose)

### Endpoints principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/health` | Estado del sistema |
| `POST` | `/auth/login` | Autenticación de usuario |
| `GET` | `/slices` | Listar slices |
| `POST` | `/slices` | Crear nuevo slice |
| `GET` | `/images` | Gestión de imágenes |
| `POST` | `/networks` | Configuración de red |

## 🚀 Despliegue en producción

### Con Docker (recomendado)

```bash
# Construir imagen
docker build -t orquestador-cloud:v3 .

# Ejecutar contenedor
docker run -d \
  --name orquestador \
  -p 8000:8000 \
  --env-file .env.local \
  orquestador-cloud:v3
```

### Con systemd

```bash
# Copiar archivo de servicio
sudo cp scripts/orquestador.service /etc/systemd/system/

# Habilitar y iniciar servicio
sudo systemctl enable orquestador
sudo systemctl start orquestador

# Verificar estado
sudo systemctl status orquestador
```

## 🔐 Seguridad

### Mejores prácticas

- ✅ **Credenciales**: Nunca incluyas credenciales en el código fuente
- ✅ **Variables de entorno**: Usa `.env.local` para configuración local
- ✅ **HTTPS**: Siempre usa HTTPS en producción
- ✅ **Firewall**: Configura reglas de firewall apropiadas
- ✅ **Actualizaciones**: Mantén dependencias actualizadas con Dependabot

### Auditoria de seguridad

```bash
# Escanear vulnerabilidades en dependencias
pip-audit

# Análisis estático de código
bandit -r . -f json -o security-report.json
```

## 🐛 Solución de problemas

### Problemas comunes

**Error de conexión a OpenStack:**
```bash
# Verificar variables de entorno
env | grep OS_

# Probar conectividad
openstack server list
```

**Puerto en uso:**
```bash
# Encontrar proceso usando el puerto
lsof -i :8000

# Cambiar puerto en configuración
export PORT=8080
```

**Problemas de permisos:**
```bash
# Verificar permisos de archivos de configuración
chmod 600 .env.local
chmod +x start.sh init_services.sh
```

### Logs y debugging

```bash
# Ver logs del servicio
tail -f logs/orquestador.log

# Debug mode
DEBUG=true python api_gateway.py

# Logs de Gunicorn
gunicorn --log-level debug -c gunicorn.conf.py wsgi:app
```

## 🗺️ Roadmap

### v3.1 (Próximamente)
- [ ] 🐳 Soporte completo de Docker/Kubernetes
- [ ] 📊 Dashboard web de administración
- [ ] 🔄 CI/CD con GitHub Actions
- [ ] 📈 Métricas y monitoreo con Prometheus

### v3.2 (Futuro)
- [ ] 🔌 Sistema de plugins extensible
- [ ] 📱 API GraphQL
- [ ] 🌍 Soporte multi-cloud (AWS, Azure, GCP)
- [ ] 🤖 Integración con Terraform/Ansible

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Por favor:

1. 🍴 Fork el proyecto
2. 🔀 Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. ✅ Ejecuta las pruebas (`pytest`)
4. 💾 Commit tus cambios (`git commit -m 'Add AmazingFeature'`)
5. 📤 Push a la rama (`git push origin feature/AmazingFeature`)
6. 🔄 Abre un Pull Request

### Estándares de código

```bash
# Formatear código
black .
isort .

# Verificar estilo
flake8
pylint src/
```

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

## 🙏 Agradecimientos

- Equipo de desarrollo de PUCP
- Comunidad de OpenStack
- Contribuidores del proyecto

## 📞 Soporte

- 📧 **Email**: support@orquestador-cloud.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/jchapo/Orquestador_Cloud_v3/issues)
- 📖 **Wiki**: [Documentación completa](https://github.com/jchapo/Orquestador_Cloud_v3/wiki)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/jchapo/Orquestador_Cloud_v3/discussions)

---

<div align="center">

**¿Te gustó el proyecto? ¡Dale una ⭐!**

[Documentación](./API_DOCUMENTATION.md) • [Contribuir](#-contribución) • [Reportar Bug](https://github.com/jchapo/Orquestador_Cloud_v3/issues)

</div>
