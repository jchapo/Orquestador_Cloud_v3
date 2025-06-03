# PUCP Cloud Orchestrator - API Documentation

## Base URL
```
http://your-gateway-ip/api
```

## Authentication
All endpoints except `/auth/login` and `/auth/register` require a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

## Core Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration

### Slice Management (R1, R1B, R1C)
- `GET /api/slices` - List user's slices
- `POST /api/slices` - Create new slice
- `GET /api/slices/{id}` - Get slice details
- `PUT /api/slices/{id}` - Update slice
- `DELETE /api/slices/{id}` - Delete slice
- `POST /api/slices/{id}/deploy` - Deploy slice to infrastructure

### Templates (Predefined Topologies)
- `GET /api/templates` - List available templates (linear, mesh, tree, ring, bus)
- `POST /api/templates` - Create custom template
- `GET /api/templates/{id}` - Get template details
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template

### Network Management (R5)
- `GET /api/networks` - List networks
- `POST /api/networks` - Create network/VLAN
- `GET /api/networks/{id}` - Get network details
- `PUT /api/networks/{id}` - Update network
- `DELETE /api/networks/{id}` - Delete network

### Image Management
- `GET /api/images` - List VM images
- `POST /api/images` - Upload new image
- `GET /api/images/{id}` - Get image details
- `DELETE /api/images/{id}` - Delete image

### Resource Monitoring (R4)
- `GET /api/resources` - Get cluster resources status
- `GET /api/resources/linux` - Linux cluster resources
- `GET /api/resources/openstack` - OpenStack cluster resources

## Example Payloads

### Login Request
```json
{
    "username": "student1",
    "password": "password123"
}
```

### Create Slice Request
```json
{
    "name": "my-lab-topology",
    "description": "Lab topology for testing",
    "template_id": "linear-3-nodes",
    "infrastructure": "linux", // or "openstack"
    "availability_zone": "zone1",
    "nodes": [
        {
            "name": "vm1",
            "image": "ubuntu-20.04",
            "flavor": "small",
            "networks": ["net1"]
        },
        {
            "name": "vm2", 
            "image": "ubuntu-20.04",
            "flavor": "small",
            "networks": ["net1", "net2"]
        }
    ],
    "networks": [
        {
            "name": "net1",
            "cidr": "192.168.1.0/24",
            "gateway": "192.168.1.1"
        }
    ]
}
```

### Create Network Request
```json
{
    "name": "lab-network-1",
    "cidr": "192.168.10.0/24",
    "gateway": "192.168.10.1",
    "vlan_id": 100,
    "infrastructure": "linux"
}
```

## Response Formats

### Success Response
```json
{
    "status": "success",
    "data": { ... },
    "request_id": "uuid"
}
```

### Error Response
```json
{
    "status": "error",
    "message": "Error description",
    "error_code": "ERROR_CODE",
    "request_id": "uuid"
}
```

## Status Codes
- `200` - OK
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `500` - Internal Server Error
- `503` - Service Unavailable
