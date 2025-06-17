#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Script de Verificación de VMs
Objetivo: Monitorear el estado de las VMs de un slice específico
          hasta que estén 'running' y tengan una IP asignada,
          o hasta que se cumpla un timeout.
"""

import requests
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, Optional, List

# --- Configuración ---
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"
DEFAULT_TIMEOUT_SECONDS = 300 # 5 minutos para esperar que las VMs se levanten
POLLING_INTERVAL_SECONDS = 10 # Intervalo de tiempo entre cada verificación

# --- Clase de Verificación ---
class VmStatusVerifier:
    def __init__(self, slice_id: str):
        self.slice_id = slice_id
        self.token = None
        self.session = requests.Session()
        self.results = {
            "slice_id": slice_id,
            "verification_start_time": None,
            "verification_end_time": None,
            "final_status": "PENDING",
            "vm_details": [],
            "logs": []
        }

    def log(self, message: str, level: str = "INFO", details: Dict = None):
        """Registra mensajes y detalles para el reporte."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "details": details or {}
        }
        self.results["logs"].append(log_entry)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {level}: {message}")
        if details:
            for k, v in details.items():
                print(f"  {k}: {v}")

    def authenticate(self) -> bool:
        """Autentica con el sistema para obtener un token JWT."""
        login_data = {
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }
        self.log("Intentando autenticar con el orquestador...", "INFO", {"username": TEST_USERNAME})
        try:
            response = self.session.post(f"{API_BASE}/auth/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                self.log("Autenticación exitosa.", "INFO", {"token_received": bool(self.token)})
                return True
            else:
                self.log(f"Fallo en la autenticación: HTTP {response.status_code}", "ERROR", {"response": response.text})
                return False
        except requests.exceptions.ConnectionError as e:
            self.log(f"Error de conexión al autenticar: {e}", "CRITICAL")
            return False
        except Exception as e:
            self.log(f"Error inesperado durante la autenticación: {e}", "ERROR")
            return False

    def get_slice_details(self) -> Optional[Dict]:
        """Obtiene los detalles de un slice específico."""
        if not self.token:
            self.log("No hay token de autenticación disponible.", "ERROR")
            return None
        
        try:
            response = self.session.get(f"{API_BASE}/slices/{self.slice_id}")
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.log(f"Slice con ID '{self.slice_id}' no encontrado.", "ERROR")
                return None
            else:
                self.log(f"Error al obtener detalles del slice: HTTP {response.status_code}", "ERROR", {"response": response.text})
                return None
        except requests.exceptions.ConnectionError as e:
            self.log(f"Error de conexión al obtener detalles del slice: {e}", "CRITICAL")
            return None
        except Exception as e:
            self.log(f"Error inesperado al obtener detalles del slice: {e}", "ERROR")
            return None

    def verify_vms(self) -> Dict:
        """
        Verifica que todas las VMs del slice estén en estado 'running' y tengan IP.
        Devuelve un diccionario con el estado general y detalles de las VMs.
        """
        slice_data = self.get_slice_details()
        if not slice_data:
            self.results["final_status"] = "ERROR_GETTING_SLICE"
            return {"status": "FAIL", "reason": "No se pudieron obtener los detalles del slice."}

        current_slice_status = slice_data.get('status')
        nodes = slice_data.get('nodes', [])
        
        self.log(f"Estado actual del slice: {current_slice_status}", "INFO", {"nodes_count": len(nodes)})

        all_vms_ok = True
        vm_details_list = []
        for node in nodes:
            vm_status = node.get('status', 'unknown')
            vm_name = node.get('name', 'N/A')
            vm_ip = node.get('ip_address', 'N/A')
            vm_console = node.get('console_url', 'N/A')

            current_vm_detail = {
                "name": vm_name,
                "status": vm_status,
                "ip_address": vm_ip,
                "console_url": vm_console
                # Aquí puedes añadir más detalles que el orquestador pueda proporcionar
            }
            vm_details_list.append(current_vm_detail)

            # Criterios de éxito: status 'running' y IP asignada
            if vm_status != 'running' or not vm_ip or vm_ip == 'N/A':
                self.log(f"VM '{vm_name}' no está lista.", "WARNING", 
                         {"expected_status": "running", "actual_status": vm_status, "ip_address": vm_ip})
                all_vms_ok = False
            else:
                self.log(f"VM '{vm_name}' lista.", "INFO", 
                         {"status": vm_status, "ip_address": vm_ip})
        
        self.results["vm_details"] = vm_details_list
        
        if all_vms_ok and current_slice_status == 'active':
            self.log("Todas las VMs están 'running' y tienen IP. Slice 'active'.", "SUCCESS")
            return {"status": "PASS", "details": {"nodes_status": vm_details_list}}
        elif current_slice_status == 'error' or current_slice_status == 'failed':
            self.log(f"El slice entró en estado de error/fallido: {current_slice_status}", "CRITICAL", {"error_message": slice_data.get('error_message')})
            return {"status": "FAIL", "reason": f"Slice en estado de error: {current_slice_status}", "details": {"nodes_status": vm_details_list, "error_message": slice_data.get('error_message')}}
        else:
            self.log("Las VMs o el slice aún no están en el estado deseado.", "INFO", 
                     {"current_slice_status": current_slice_status, "all_vms_ok": all_vms_ok})
            return {"status": "IN_PROGRESS", "details": {"nodes_status": vm_details_list}}


    def run_verification(self, timeout: int = DEFAULT_TIMEOUT_SECONDS):
        """Ejecuta el proceso de verificación con reintentos."""
        self.results["verification_start_time"] = datetime.now().isoformat()
        
        self.log(f"Iniciando verificación para slice ID: {self.slice_id}")

        if not self.authenticate():
            self.results["final_status"] = "AUTH_FAILED"
            return
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            verification_result = self.verify_vms()
            
            if verification_result["status"] == "PASS":
                self.results["final_status"] = "PASSED"
                self.log("Verificación completada: Todas las VMs están activas.", "SUCCESS")
                break
            elif verification_result["status"] == "FAIL":
                self.results["final_status"] = "FAILED"
                self.log(f"Verificación fallida: {verification_result.get('reason', 'Razón desconocida')}", "ERROR", verification_result.get('details'))
                break # Fallo definitivo, no tiene sentido seguir esperando
            else: # IN_PROGRESS
                remaining_time = int(timeout - (time.time() - start_time))
                self.log(f"VMs aún no listas. Reintentando en {POLLING_INTERVAL_SECONDS} segundos. Tiempo restante: {remaining_time}s", "INFO")
                time.sleep(POLLING_INTERVAL_SECONDS)
        else:
            self.results["final_status"] = "TIMEOUT"
            self.log(f"Tiempo de espera ({timeout}s) excedido. Las VMs no alcanzaron el estado deseado.", "ERROR")
            self.verify_vms() # Última verificación para capturar el estado final

        self.results["verification_end_time"] = datetime.now().isoformat()
        self.generate_report()
        self.save_report()

    def generate_report(self):
        """Genera un resumen del proceso de verificación."""
        print("\n--- REPORTE DE VERIFICACIÓN DE VMS ---")
        print(f"Slice ID: {self.results['slice_id']}")
        print(f"Estado Final: {self.results['final_status']}")
        print(f"Inicio: {self.results['verification_start_time']}")
        print(f"Fin: {self.results['verification_end_time']}")
        
        if self.results['vm_details']:
            print("\nDetalles de VMs:")
            for vm in self.results['vm_details']:
                print(f"  - VM: {vm.get('name', 'N/A')}")
                print(f"    Estado: {vm.get('status', 'N/A')}")
                print(f"    IP: {vm.get('ip_address', 'N/A')}")
                if vm.get('console_url'):
                    print(f"    Consola: {vm.get('console_url')}")
        else:
            print("\nNo se encontraron detalles de VMs o no se pudo acceder a ellos.")

        print("\n--- Fin del Reporte ---")

    def save_report(self):
        """Guarda los resultados completos en un archivo JSON."""
        filename = f"vm_verification_report_{self.slice_id}_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.log(f"Reporte de verificación guardado en: {filename}", "INFO")
        except Exception as e:
            self.log(f"Error al guardar el reporte: {e}", "ERROR")

# --- Función Principal ---
def main():
    if len(sys.argv) < 2:
        print("Uso: python3 verify_vm_status.py <SLICE_ID> [TIMEOUT_SEGS]")
        print("Ejemplo: python3 verify_vm_status.py 465579d9-b281-4330-8e7e-7b1b17c8903d")
        print("Ejemplo con timeout: python3 verify_vm_status.py 465579d9-b281-4330-8e7e-7b1b17c8903d 600")
        sys.exit(1)

    slice_id = sys.argv[1]
    timeout = DEFAULT_TIMEOUT_SECONDS
    if len(sys.argv) > 2:
        try:
            timeout = int(sys.argv[2])
        except ValueError:
            print("TIMEOUT_SEGS debe ser un número entero.")
            sys.exit(1)

    verifier = VmStatusVerifier(slice_id)
    verifier.run_verification(timeout)

    if verifier.results["final_status"] == "PASSED":
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
