#!/usr/bin/env python3
"""
Monitor en tiempo real del estado de topologías
"""

import requests
import time
import json
import sys
from datetime import datetime

API_BASE = "http://localhost/api"

def get_auth_token():
    """Obtener token de autenticación"""
    login_data = {"username": "testuser", "password": "testpass123"}
    
    try:
        response = requests.post(f"{API_BASE}/auth/login", json=login_data)
        if response.status_code == 200:
            return response.json().get('token')
    except Exception as e:
        print(f"Error de autenticación: {e}")
    
    return None

def monitor_slices(token):
    """Monitorear todos los slices activos"""
    headers = {'Authorization': f'Bearer {token}'}
    
    print("🔍 Monitor de Topologías PUCP")
    print("=" * 50)
    
    while True:
        try:
            # Obtener lista de slices
            response = requests.get(f"{API_BASE}/slices", headers=headers)
            
            if response.status_code == 200:
                slices = response.json()
                
                # Limpiar pantalla
                print("\033[2J\033[H")
                print(f"🔍 Monitor de Topologías PUCP - {datetime.now().strftime('%H:%M:%S')}")
                print("=" * 70)
                
                if not slices:
                    print("📭 No hay slices activos")
                else:
                    print(f"📊 Total de slices: {len(slices)}")
                    print()
                    
                    for slice_data in slices:
                        status = slice_data.get('status', 'unknown')
                        status_icon = {
                            'draft': '📝',
                            'validating': '🔍', 
                            'deploying': '🚀',
                            'active': '✅',
                            'error': '❌',
                            'deleted': '🗑️'
                        }.get(status, '❓')
                        
                        print(f"{status_icon} {slice_data['name']} ({slice_data['id'][:8]})")
                        print(f"   Status: {status}")
                        print(f"   Infraestructura: {slice_data.get('infrastructure', 'N/A')}")
                        print(f"   Nodos: {slice_data.get('node_count', 0)}")
                        print(f"   Creado: {slice_data.get('created_at', 'N/A')}")
                        
                        if slice_data.get('error_message'):
                            print(f"   ⚠️ Error: {slice_data['error_message']}")
                        
                        print()
                
                # Mostrar recursos del sistema
                resource_response = requests.get(f"{API_BASE}/resources?infrastructure=linux", headers=headers)
                if resource_response.status_code == 200:
                    resources = resource_response.json()
                    
                    print("🖥️ Estado del Cluster:")
                    for server in resources.get('servers', []):
                        cpu_usage = server.get('cpu_utilization', 0)
                        ram_usage = server.get('ram_utilization', 0)
                        
                        cpu_bar = "█" * int(cpu_usage/10) + "░" * (10 - int(cpu_usage/10))
                        ram_bar = "█" * int(ram_usage/10) + "░" * (10 - int(ram_usage/10))
                        
                        print(f"   {server['hostname']}: CPU [{cpu_bar}] {cpu_usage:.1f}% | RAM [{ram_bar}] {ram_usage:.1f}%")
                
                print("\n" + "=" * 70)
                print("⏰ Actualizando cada 10 segundos... (Ctrl+C para salir)")
                
            time.sleep(10)
            
        except KeyboardInterrupt:
            print("\n👋 Monitor detenido")
            break
        except Exception as e:
            print(f"❌ Error en monitor: {e}")
            time.sleep(5)

def main():
    token = get_auth_token()
    if not token:
        print("❌ No se pudo obtener token de autenticación")
        sys.exit(1)
    
    monitor_slices(token)

if __name__ == '__main__':
    main()
