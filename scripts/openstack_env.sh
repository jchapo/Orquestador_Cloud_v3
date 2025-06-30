#!/bin/bash

# Variables de entorno OpenStack para acceso vía túnel SSH
export OS_AUTH_URL=http://localhost:5000/v3
export OS_PROJECT_NAME=admin
export OS_USERNAME=admin
export OS_PASSWORD=openstack123
export OS_USER_DOMAIN_NAME=Default
export OS_PROJECT_DOMAIN_NAME=Default
export OS_IDENTITY_API_VERSION=3
export OS_REGION_NAME=RegionOne

echo "✅ Variables de entorno OpenStack configuradas"
echo "   - Auth URL: $OS_AUTH_URL"
echo "   - Project: $OS_PROJECT_NAME"
echo "   - User: $OS_USERNAME"
