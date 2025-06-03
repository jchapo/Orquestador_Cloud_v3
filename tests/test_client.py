#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Test Client
"""

import requests
import json
import sys

class PUCPOrchestatorClient:
    def __init__(self, base_url="http://localhost/api"):
        self.base_url = base_url
        self.token = None
        self.session = requests.Session()
    
    def login(self, username, password):
        """Login and store token"""
        response = self.session.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password
        })
        
        if response.status_code == 200:
            data = response.json()
            self.token = data.get('token')
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            print(f"✓ Logged in as {username}")
            return True
        else:
            print(f"✗ Login failed: {response.text}")
            return False
    
    def register(self, username, password, email, role="student"):
        """Register new user"""
        response = self.session.post(f"{self.base_url}/auth/register", json={
            "username": username,
            "password": password,
            "email": email,
            "role": role
        })
        
        if response.status_code == 201:
            print(f"✓ User {username} registered successfully")
            return True
        else:
            print(f"✗ Registration failed: {response.text}")
            return False
    
    def create_slice(self, slice_data):
        """Create a new slice"""
        response = self.session.post(f"{self.base_url}/slices", json=slice_data)
        if response.status_code in [200, 201]:
            print("✓ Slice created successfully")
            return response.json()
        else:
            print(f"✗ Slice creation failed: {response.text}")
            return None
    
    def list_slices(self):
        """List user's slices"""
        response = self.session.get(f"{self.base_url}/slices")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"✗ Failed to list slices: {response.text}")
            return None
    
    def deploy_slice(self, slice_id):
        """Deploy a slice"""
        response = self.session.post(f"{self.base_url}/slices/{slice_id}/deploy")
        if response.status_code == 200:
            print(f"✓ Slice {slice_id} deployment started")
            return response.json()
        else:
            print(f"✗ Slice deployment failed: {response.text}")
            return None
    
    def get_resources(self):
        """Get resource information"""
        response = self.session.get(f"{self.base_url}/resources")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"✗ Failed to get resources: {response.text}")
            return None

def main():
    client = PUCPOrchestatorClient()
    
    # Test registration and login
    print("=== Testing PUCP Cloud Orchestrator Client ===")
    
    # Register test user
    client.register("testuser2", "testpass123", "test2@pucp.edu.pe")
    
    # Login
    if not client.login("testuser2", "testpass123"):
        sys.exit(1)
    
    # List slices
    print("\nListing slices...")
    slices = client.list_slices()
    if slices:
        print(json.dumps(slices, indent=2))
    
    # Create a test slice
    print("\nCreating test slice...")
    test_slice = {
        "name": "test-linear-topology",
        "description": "Test linear topology with 3 VMs",
        "template": "linear",
        "infrastructure": "linux",
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
            },
            {
                "name": "vm3",
                "image": "ubuntu-20.04",
                "flavor": "small", 
                "networks": ["net2"]
            }
        ],
        "networks": [
            {
                "name": "net1",
                "cidr": "192.168.1.0/24"
            },
            {
                "name": "net2", 
                "cidr": "192.168.2.0/24"
            }
        ]
    }
    
    slice_result = client.create_slice(test_slice)
    if slice_result:
        print(json.dumps(slice_result, indent=2))
    
    # Get resources
    print("\nGetting resource information...")
    resources = client.get_resources()
    if resources:
        print(json.dumps(resources, indent=2))

if __name__ == "__main__":
    main()
