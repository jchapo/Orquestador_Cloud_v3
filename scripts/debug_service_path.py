#!/usr/bin/env python3
"""Debug del PATH en el servicio"""

import os
import subprocess
import sys

print("=== DEBUG SERVICE ENVIRONMENT ===")
print(f"Python executable: {sys.executable}")
print(f"Current user: {os.getenv('USER', 'unknown')}")
print(f"Home directory: {os.getenv('HOME', 'unknown')}")
print(f"Current PATH: {os.getenv('PATH', 'unknown')}")
print()

# Buscar SSH en diferentes ubicaciones
ssh_locations = [
    '/usr/bin/ssh',
    '/bin/ssh', 
    '/usr/local/bin/ssh'
]

print("SSH executable search:")
for location in ssh_locations:
    if os.path.exists(location):
        print(f"✅ Found: {location}")
    else:
        print(f"❌ Not found: {location}")

print()

# Usar which para encontrar SSH
try:
    result = subprocess.run(['which', 'ssh'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✅ which ssh: {result.stdout.strip()}")
    else:
        print("❌ which ssh failed")
except Exception as e:
    print(f"❌ Error running which: {e}")

# Usar whereis
try:
    result = subprocess.run(['whereis', 'ssh'], capture_output=True, text=True)
    print(f"whereis ssh: {result.stdout.strip()}")
except Exception as e:
    print(f"Error running whereis: {e}")
