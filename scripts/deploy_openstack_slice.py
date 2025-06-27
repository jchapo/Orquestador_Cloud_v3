#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import json
import time
import argparse

API_BASE = "http://localhost/api"
USERNAME = "testuser"
PASSWORD = "testpass123"

def authenticate():
    response = requests.post(f"{API_BASE}/auth/login", json={
        "username": USERNAME,
        "password": PASSWORD
    })
    
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(f"Autenticación fallida: {response.text}")
        return None

def create_slice(token, topology_type='linear', num_vms=3):
    headers = {'Authorization': f'Bearer {token}'}
    
    slice_data = {
        "name": f"openstack-{topology_type}-{int(time.time())}",
        "description": f"Topología de prueba {topology_type} en OpenStack",
        "infrastructure": "openstack",
        "template_id": f"{topology_type}-{num_vms}-nodes",
        "placement_policy": "balanced",
        "availability_zone": "nova"
    }
    
    print(f"Creando slice {topology_type} con {num_vms} VMs en OpenStack...")
    
    response = requests.post(
        f"{API_BASE}/slices",
        json=slice_data,
        headers=headers
    )
    
    if response.status_code == 201:
        slice_info = response.json()
        print(f"Slice creado: {slice_info['id']}")
        return slice_info['id']
    else:
        print(f"Error al crear el slice: {response.text}")
        return None

def deploy_slice(token, slice_id):
    headers = {'Authorization': f'Bearer {token}'}
    
    print(f"Desplegando slice {slice_id}...")
    
    response = requests.post(
        f"{API_BASE}/slices/{slice_id}/deploy",
        headers=headers
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"Despliegue iniciado: {result['status']}")
        return True
    else:
        print(f"Error al desplegar el slice: {response.text}")
        return False

def check_slice_status(token, slice_id):
    headers = {'Authorization': f'Bearer {token}'}
    
    print(f"Comprobando el estado del slice...")
    
    max_attempts = 60  # 5 minutos máximo
    for i in range(max_attempts):
        response = requests.get(
            f"{API_BASE}/slices/{slice_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            slice_data = response.json()
            status = slice_data['status']
            
            print(f"Estado: {status}")
            
            if status == 'running':
                print("¡El slice está en ejecución!")
                
                if 'vms' in slice_data:
                    print("\nDetalles de las VMs:")
                    for vm in slice_data['vms']:
                        print(f"  - {vm['name']}: {vm.get('status', 'desconocido')} "
                              f"(IP: {vm.get('ip_address', 'pendiente')})")
                
                if 'console_urls' in slice_data:
                    print("\nURLs de la consola:")
                    for vm_name, url in slice_data['console_urls'].items():
                        print(f"  - {vm_name}: {url}")
                
                return True
            elif status == 'error':
                print("Despliegue fallido")
                if 'error_message' in slice_data:
                    print(f"Error: {slice_data['error_message']}")
                return False
            
            time.sleep(5)
        else:
            print(f"Error al obtener el estado del slice: {response.text}")
            return False
    
    print("Tiempo de espera agotado mientras se esperaba el despliegue")
    return False

def list_slices(token):
    headers = {'Authorization': f'Bearer {token}'}
    
    response = requests.get(f"{API_BASE}/slices", headers=headers)
    
    if response.status_code == 200:
        slices = response.json()
        print(f"\nSe encontraron {len(slices)} slices:")
        for s in slices:
            print(f"  - {s['name']} ({s['id']}): {s['status']} en {s['infrastructure']}")
    else:
        print(f"Error al listar los slices: {response.text}")

def delete_slice(token, slice_id):
    headers = {'Authorization': f'Bearer {token}'}
    
    print(f"Eliminando el slice {slice_id}...")
    
    response = requests.delete(
        f"{API_BASE}/slices/{slice_id}",
        headers=headers
    )
    
    if response.status_code == 200:
        print("Slice eliminado exitosamente")
        return True
    else:
        print(f"Error al eliminar el slice: {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Desplegar slice de OpenStack a través de la API')
    parser.add_argument('--topology', choices=['linear', 'star', 'ring', 'mesh', 'bus'],
                       default='linear', help='Tipo de topología')
    parser.add_argument('--vms', type=int, default=3, help='Número de VMs')
    parser.add_argument('--list', action='store_true', help='Listar slices existentes')
    parser.add_argument('--delete', help='Eliminar slice por ID')
    
    args = parser.parse_args()
    
    token = authenticate()
    if not token:
        return
    
    if args.list:
        list_slices(token)
        return
    
    if args.delete:
        delete_slice(token, args.delete)
        return
    
    print(f"\nDesplegando topología {args.topology} con {args.vms} VMs en OpenStack")
    print("=" * 60)
    
    slice_id = create_slice(token, args.topology, args.vms)
    if not slice_id:
        return
    
    if not deploy_slice(token, slice_id):
        return
    
    time.sleep(5)
    success = check_slice_status(token, slice_id)
    
    if success:
        print("\n¡Despliegue exitoso!")
        print(f"Slice ID: {slice_id}")
        print("\nPara eliminar este slice, ejecute:")
        print(f"  python3 {sys.argv[0]} --delete {slice_id}")
    else:
        print("\nDespliegue fallido")
        delete_slice(token, slice_id)

if __name__ == '__main__':
    main()