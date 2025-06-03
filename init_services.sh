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