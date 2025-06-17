#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Test Case 2.1.1
Caso 2.1.1 - Creación y Despliegue de slice básico
Objetivo: Verificar creación y despliegue de slice con configuración mínima válida
"""

import requests
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, Optional, List

# Configuración
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

class TestCase211:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.1.1",
            "objective": "Verificar creación y despliegue de slice con configuración mínima válida",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": []
        }
        
    def log_step(self, step_number: int, description: str, status: str, details: Dict = None):
        """Registrar paso del test"""
        step = {
            "step": step_number,
            "description": description,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        self.test_results["steps"].append(step)
        # Usar colores para mejor visibilidad en la consola
        status_color = "\033[92mPASS\033[0m" if status == "PASS" else "\033[91mFAIL\033[0m" if status == "FAIL" else "\033[93m" + status + "\033[0m"
        print(f"📋 Paso {step_number}: {description} - {status_color}")
        if details:
            for key, value in details.items():
                # Formatear la impresión de detalles si es un diccionario grande (como nodos)
                if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict) and 'name' in value[0]:
                    print(f"    {key}:")
                    for item in value:
                        print(f"      - Nombre: {item.get('name')}, Estado: {item.get('status')}, IP: {item.get('ip_address', 'N/A')}")
                else:
                    print(f"    {key}: {value}")
    
    def add_evidence(self, evidence_type: str, content: Dict):
        """Agregar evidencia del test"""
        evidence = {
            "type": evidence_type,
            "timestamp": datetime.now().isoformat(),
            "content": content
        }
        self.test_results["evidences"].append(evidence)
    
    def authenticate(self) -> bool:
        """Autenticar con el sistema"""
        login_data = {
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD
        }
        
        try:
            response = self.session.post(f"{API_BASE}/auth/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                self.add_evidence("authentication", {"request": login_data, "response": data})
                return True
            else:
                self.add_evidence("authentication_error", {"request": login_data, "response": response.text})
                return False
                
        except Exception as e:
            self.add_evidence("authentication_error", {"request": login_data, "error": str(e)})
            return False
            
    def check_prerequisites(self) -> bool:
        """Verificar prerrequisitos del test"""
        print("🔍 VERIFICANDO PRERREQUISITOS")
        print("-" * 40)
        
        prerequisites_ok = True
        
        # Prerrequisito 1: Usuario autenticado (token JWT válido)
        print("1. Verificando autenticación...")
        if self.authenticate():
            self.log_step(0, "Prerrequisito: Autenticación", "PASS", 
                          {"username": TEST_USERNAME, "token_received": bool(self.token)})
        else:
            self.log_step(0, "Prerrequisito: Autenticación", "FAIL")
            prerequisites_ok = False
        
        # Prerrequisito 2: Base de datos slice_service.db inicializada
        print("2. Verificando base de datos...")
        try:
            response = self.session.get(f"{API_BASE}/../health")
            if response.status_code == 200:
                health_data = response.json()
                self.log_step(0, "Prerrequisito: Base de datos", "PASS", 
                              {"health_status": health_data})
                self.add_evidence("health_check", health_data)
            else:
                self.log_step(0, "Prerrequisito: Base de datos", "FAIL", 
                              {"error": response.text})
                prerequisites_ok = False
        except Exception as e:
            self.log_step(0, "Prerrequisito: Base de datos", "FAIL", 
                          {"error": str(e)})
            prerequisites_ok = False
        
        # Prerrequisito 3: Al menos un servidor disponible
        print("3. Verificando servidores disponibles...")
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                servers = resources.get('servers', [])
                if servers:
                    self.log_step(0, "Prerrequisito: Servidores disponibles", "PASS", 
                                  {"servers_count": len(servers), "servers": servers})
                    self.add_evidence("available_resources", resources)
                else:
                    self.log_step(0, "Prerrequisito: Servidores disponibles", "FAIL", 
                                  {"error": "No hay servidores disponibles"})
                    prerequisites_ok = False
            else:
                self.log_step(0, "Prerrequisito: Servidores disponibles", "FAIL", 
                              {"error": response.text})
                prerequisites_ok = False
        except Exception as e:
            self.log_step(0, "Prerrequisito: Servidores disponibles", "FAIL", 
                          {"error": str(e)})
            prerequisites_ok = False
        
        return prerequisites_ok
    
    def execute_test_procedure(self) -> bool:
        """Ejecutar procedimiento del test (creación y despliegue)"""
        print("\n🧪 EJECUTANDO PROCEDIMIENTO DE PRUEBA")
        print("-" * 40)
        
        # Paso 1: POST /slices con payload específico
        slice_payload = {
            "name": f"test-slice-211-{int(time.time())}", # Añadir timestamp para unicidad
            "infrastructure": "linux",
            "nodes": [
                {
                    "name": "vm1",
                    "image": "ubuntu-20.04",
                    "flavor": "small"
                }
            ],
            "networks": [
                {
                    "name": "net1",
                    "cidr": "192.168.1.0/24"
                }
            ]
        }
        
        print("1. Enviando POST /slices con payload de prueba...")
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_payload)
            
            self.add_evidence("slice_creation_request", {
                "url": f"{API_BASE}/slices",
                "method": "POST",
                "payload": slice_payload,
                "response_status": response.status_code,
                "response_body": response.text
            })
            
            # Paso 2: Verificar respuesta HTTP 201
            if response.status_code == 201:
                self.log_step(1, "POST /slices", "PASS", 
                              {"status_code": response.status_code})
                self.log_step(2, "Verificar HTTP 201", "PASS", 
                              {"expected": 201, "actual": response.status_code})
            else:
                self.log_step(1, "POST /slices", "FAIL", 
                              {"status_code": response.status_code, "response": response.text})
                self.log_step(2, "Verificar HTTP 201", "FAIL", 
                              {"expected": 201, "actual": response.status_code})
                return False
            
            # Paso 3: Validar que response contiene slice_id generado
            try:
                response_data = response.json()
                slice_id = response_data.get('id')
                
                if slice_id:
                    self.slice_id = slice_id
                    self.log_step(3, "Validar slice_id generado", "PASS", 
                                  {"slice_id": slice_id})
                else:
                    self.log_step(3, "Validar slice_id generado", "FAIL", 
                                  {"response": response_data})
                    return False
                
                # Paso 4: Verificar que se calcularon recursos totales correctamente
                expected_resources = {
                    "total_vcpus": 2,
                    "total_ram": 2048,
                    "total_disk": 10
                }
                
                actual_resources = response_data.get('resources', {})
                resources_match = True
                resource_details = {}
                
                for resource, expected_value in expected_resources.items():
                    actual_value = actual_resources.get(resource)
                    resource_details[f"{resource}_expected"] = expected_value
                    resource_details[f"{resource}_actual"] = actual_value
                    resource_details[f"{resource}_match"] = actual_value == expected_value
                    
                    if actual_value != expected_value:
                        resources_match = False
                
                if resources_match:
                    self.log_step(4, "Verificar recursos calculados", "PASS", resource_details)
                else:
                    self.log_step(4, "Verificar recursos calculados", "FAIL", resource_details)
                    return False
                
                # Paso 5: Verificar estado del slice después de la creación
                slice_status = response_data.get('status')
                if slice_status == 'draft':
                    self.log_step(5, "Verificar estado 'draft' inicial del slice", "PASS", 
                                  {"expected": "draft", "actual": slice_status})
                else:
                    self.log_step(5, "Verificar estado 'draft' inicial del slice", "FAIL", 
                                  {"expected": "draft", "actual": slice_status})
                    return False
                
                self.add_evidence("slice_creation_response", response_data)

                # --- NUEVOS PASOS PARA DESPLIEGUE Y VERIFICACIÓN DE VMs ---

                # Paso 6: POST /slices/{slice_id}/deploy para iniciar el despliegue
                print(f"\n6. Desplegando slice {self.slice_id}...")
                deploy_response = self.session.post(f"{API_BASE}/slices/{self.slice_id}/deploy")
                
                self.add_evidence("slice_deployment_request", {
                    "url": f"{API_BASE}/slices/{self.slice_id}/deploy",
                    "method": "POST",
                    "response_status": deploy_response.status_code,
                    "response_body": deploy_response.text
                })

                if deploy_response.status_code == 200:
                    deploy_result = deploy_response.json()
                    self.log_step(6, "Solicitar despliegue del slice", "PASS", 
                                  {"status_code": deploy_response.status_code, "deployment_status_initial": deploy_result.get('status')})
                    # Imprimir el estado inicial de las VMs si la respuesta lo incluye
                    deployed_vms_initial = deploy_result.get('deployment_result', {}).get('deployed_vms', [])
                    if deployed_vms_initial:
                        self.log_step(6.1, "Estado inicial de VMs después de solicitud de despliegue", "INFO",
                                      {"deployed_vms": deployed_vms_initial})
                else:
                    self.log_step(6, "Solicitar despliegue del slice", "FAIL", 
                                  {"status_code": deploy_response.status_code, "response": deploy_response.text})
                    return False

                # Paso 7: Monitorear el despliegue hasta que el slice esté 'active'
                print(f"\n7. Monitoreando despliegue de slice {self.slice_id} (timeout: 300s)...")
                if not self.monitor_slice_deployment(self.slice_id, timeout=300):
                    self.log_step(7, "Monitorear despliegue del slice", "FAIL", {"reason": "Deployment timed out or failed"})
                    return False
                self.log_step(7, "Monitorear despliegue del slice", "PASS", {"status": "active"})

                # Paso 8: Verificar que las VMs individuales estén 'running' y tengan IPs
                print(f"\n8. Verificando estado final de VMs en el slice {self.slice_id}...")
                final_verification_result = self.verify_deployed_vms_status(self.slice_id)
                if final_verification_result["status"] == "PASS":
                    self.log_step(8, "Verificar VMs desplegadas y activas", "PASS", final_verification_result["details"])
                    return True # Todas las verificaciones pasaron
                else:
                    self.log_step(8, "Verificar VMs desplegadas y activas", "FAIL", final_verification_result["details"])
                    return False # Alguna VM no está running o faltan IPs
                
            except json.JSONDecodeError:
                self.log_step(3, "Validar response JSON", "FAIL", 
                              {"error": "Response no es JSON válido"})
                return False
                
        except Exception as e:
            self.log_step(1, "POST /slices", "FAIL", {"error": str(e)})
            return False
    
    def monitor_slice_deployment(self, slice_id: str, timeout: int = 300) -> bool:
        """Monitorear el progreso del deployment del slice hasta que esté 'active'"""
        start_time = time.time()
        last_status = None
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(f"{API_BASE}/slices/{slice_id}")
                
                if response.status_code == 200:
                    slice_data = response.json()
                    current_status = slice_data.get('status')
                    
                    if current_status != last_status:
                        print(f"  Estado actual del slice: {current_status}")
                        last_status = current_status
                        self.add_evidence("slice_status_update", {"status": current_status, "slice_data_snapshot": slice_data})
                        
                    if current_status == 'active':
                        print("  ✅ Slice se ha activado. Despliegue completado.")
                        return True
                        
                    elif current_status == 'error':
                        error_msg = slice_data.get('error_message', 'Unknown error during deployment')
                        print(f"  ❌ Despliegue falló: {error_msg}")
                        self.add_evidence("deployment_failure", {"status": current_status, "error_message": error_msg, "slice_data_snapshot": slice_data})
                        return False
                        
                else:
                    print(f"  Error al obtener estado del slice: {response.status_code} - {response.text}")
                    self.add_evidence("monitor_error", {"status_code": response.status_code, "response": response.text})
                    return False # Error fatal al consultar el estado
                    
                time.sleep(10)  # Esperar 10 segundos entre checks
                
            except Exception as e:
                print(f"  ❌ Error monitoreando despliegue: {e}")
                self.add_evidence("monitor_exception", {"error": str(e)})
                time.sleep(5) # Esperar un poco menos si hay un error de conexión para reintentar
        
        print(f"  ⏰ Timeout después de {timeout} segundos para el despliegue del slice.")
        return False

    def verify_deployed_vms_status(self, slice_id: str) -> Dict:
        """Verificar que todas las VMs del slice estén en estado 'running' y tengan IP."""
        result = {"status": "PASS", "details": {}}
        try:
            response = self.session.get(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                slice_data = response.json()
                nodes = slice_data.get('nodes', [])
                
                expected_vm_count = 1 # Para este caso de prueba 2.1.1, solo esperamos 1 VM
                if len(nodes) != expected_vm_count:
                    result["status"] = "FAIL"
                    result["details"]["error"] = f"Número incorrecto de VMs. Esperado: {expected_vm_count}, Actual: {len(nodes)}"
                    self.add_evidence("vm_count_mismatch", result["details"])
                    return result

                all_vms_running = True
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
                    }
                    vm_details_list.append(current_vm_detail)

                    if vm_status != 'running' or not vm_ip or vm_ip == 'N/A':
                        all_vms_running = False
                        if vm_status != 'running':
                            print(f"  ❌ VM '{vm_name}' no está en estado 'running'. Estado actual: {vm_status}")
                        if not vm_ip or vm_ip == 'N/A':
                            print(f"  ❌ VM '{vm_name}' no tiene una dirección IP asignada.")
                        result["status"] = "FAIL"
                        result["details"]["reason"] = f"VM '{vm_name}' no está running o no tiene IP."
                        
                result["details"]["nodes_status"] = vm_details_list
                if all_vms_running:
                    print("  ✅ Todas las VMs están en estado 'running' y tienen IPs asignadas.")
                
                self.add_evidence("final_vm_status_check", result["details"])
                
            else:
                result["status"] = "FAIL"
                result["details"]["error"] = f"Error al obtener detalles del slice para verificación de VMs: {response.status_code} - {response.text}"
                self.add_evidence("get_slice_details_error", result["details"])

        except Exception as e:
            result["status"] = "FAIL"
            result["details"]["error"] = f"Excepción durante la verificación de VMs: {str(e)}"
            self.add_evidence("vm_verification_exception", result["details"])
        
        return result
    
    def verify_database_state(self):
        """Verificar estado en base de datos (opcional, pero útil para persistencia)"""
        print("\n🗄️ VERIFICANDO ESTADO EN BASE DE DATOS")
        print("-" * 40)
        
        if not self.slice_id:
            print("❌ No hay slice_id para verificar")
            self.log_step(9, "Verificar slice en BD (no ID)", "SKIPPED", {"reason": "No slice_id available"})
            return
            
        try:
            response = self.session.get(f"{API_BASE}/slices/{self.slice_id}")
            if response.status_code == 200:
                slice_data = response.json()
                # Aquí el estado esperado ya no es 'draft', sino 'active'
                expected_status = 'active' 
                if slice_data.get('status') == expected_status:
                    self.log_step(9, f"Verificar slice en BD (estado '{expected_status}')", "PASS", 
                                  {"slice_id": self.slice_id, "status_in_db": slice_data.get('status'), "full_data": slice_data})
                    print(f"✅ Slice {self.slice_id} encontrado en BD con estado '{expected_status}':")
                    print(f"    Nombre: {slice_data.get('name')}")
                    print(f"    Estado: {slice_data.get('status')}")
                    print(f"    Recursos: {slice_data.get('resources')}")
                    print(f"    Nodos: {len(slice_data.get('nodes', []))}")
                    for node in slice_data.get('nodes', []):
                        print(f"      - {node.get('name')}: {node.get('status')}, IP: {node.get('ip_address', 'N/A')}")
                else:
                    self.log_step(9, f"Verificar slice en BD (estado '{expected_status}')", "FAIL", 
                                  {"slice_id": self.slice_id, "status_in_db": slice_data.get('status'), "full_data": slice_data})
                    print(f"❌ Slice {self.slice_id} encontrado en BD pero con estado inesperado: {slice_data.get('status')}")
                self.add_evidence("database_verification", slice_data)
                    
            else:
                self.log_step(9, "Verificar slice en BD", "FAIL", 
                              {"error": response.text})
                print(f"❌ Error al consultar slice {self.slice_id} en BD: {response.status_code} - {response.text}")
        except Exception as e:
            self.log_step(9, "Verificar slice en BD", "FAIL", 
                          {"error": str(e)})
            print(f"❌ Excepción al verificar slice en BD: {e}")
    
    def cleanup_slice(self):
        """Intenta limpiar el slice creado si existe."""
        if self.slice_id:
            print(f"\n🧹 Limpiando slice de prueba {self.slice_id}...")
            try:
                response = self.session.delete(f"{API_BASE}/slices/{self.slice_id}")
                if response.status_code == 200:
                    self.log_step(10, "Eliminar slice", "PASS", {"slice_id": self.slice_id})
                    print(f"✅ Slice {self.slice_id} eliminado correctamente.")
                else:
                    self.log_step(10, "Eliminar slice", "FAIL", {"slice_id": self.slice_id, "error": response.text})
                    print(f"❌ Error al eliminar slice {self.slice_id}: {response.text}")
            except Exception as e:
                self.log_step(10, "Eliminar slice", "FAIL", {"slice_id": self.slice_id, "error": str(e)})
                print(f"❌ Excepción al eliminar slice {self.slice_id}: {e}")
        else:
            self.log_step(10, "Eliminar slice", "SKIPPED", {"reason": "No slice_id to delete"})
            print("No hay slice_id para eliminar.")


    def generate_test_report(self):
        """Generar reporte del test"""
        print("\n📊 REPORTE DEL TEST CASO 2.1.1")
        print("=" * 50)
        
        passed_steps = len([s for s in self.test_results["steps"] if s["status"] == "PASS"])
        total_steps = len(self.test_results["steps"])
        
        print(f"Caso de prueba: {self.test_results['case_number']}")
        print(f"Objetivo: {self.test_results['objective']}")
        print(f"Estado final: {self.test_results['status']}")
        print(f"Pasos ejecutados: {total_steps}")
        print(f"Pasos exitosos: {passed_steps}")
        print(f"Duración: {self.test_results['start_time']} - {self.test_results['end_time']}")
        
        print("\nDETALLE DE PASOS:")
        for step in self.test_results["steps"]:
            status_icon = "✅" if step["status"] == "PASS" else "❌" if step["status"] == "FAIL" else "💡"
            print(f"{status_icon} Paso {step['step']}: {step['description']} - {step['status']}")
        
        print(f"\nEVIDENCIAS RECOLECTADAS: {len(self.test_results['evidences'])}")
        # No imprimir el contenido completo de las evidencias aquí, solo el tipo y timestamp
        for i, evidence in enumerate(self.test_results["evidences"], 1):
            print(f"{i}. {evidence['type']} - {evidence['timestamp']}")
        
        if self.slice_id:
            print(f"\n🆔 SLICE FINAL: {self.slice_id}")
            if self.test_results['status'] != "PASSED" and self.slice_id: # Sugerir eliminación manual solo si falló o no se limpió
                print(f"    Para eliminar manualmente: curl -X DELETE {API_BASE}/slices/{self.slice_id} -H 'Authorization: Bearer {self.token}'")
        
    def save_test_results(self):
        """Guardar resultados del test en archivo"""
        filename = f"test_case_2_1_1_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")
    
    def run_test(self):
        """Ejecutar test completo del Caso 2.1.1"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.1.1")
        print("Creación y Despliegue de slice básico")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        test_success = False # Bandera para el estado final del test
        
        try:
            # Verificar prerrequisitos
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Ejecutar procedimiento de prueba (Creación y Despliegue)
            if self.execute_test_procedure():
                test_success = True # El despliegue y la verificación de VMs fueron exitosos
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            self.test_results["status"] = "INTERRUPTED"
            return False
        except Exception as e:
            print(f"\n💥 Error crítico en test: {e}")
            self.test_results["status"] = "ERROR"
            return False
        finally:
            self.test_results["end_time"] = datetime.now().isoformat()
            
            # Finalizar el estado del test_results basado en test_success
            if test_success:
                self.test_results["status"] = "PASSED"
                print("\n🎉 ¡TEST CASO 2.1.1 EXITOSO!")
                print("✅ Slice creado y VM desplegada exitosamente con configuración mínima válida.")
            else:
                self.test_results["status"] = "FAILED"
                print("\n❌ TEST CASO 2.1.1 FALLÓ")
                print("Verifica los pasos fallidos en el reporte para más detalles.")

            self.generate_test_report()
            self.save_test_results()

            # Limpiar el slice al final, siempre que se haya creado.
            # Puedes comentar esta línea si quieres inspeccionar el slice después de la prueba.
            self.cleanup_slice()

        return test_success

def main():
    """Función principal"""
    test = TestCase211()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.1.1 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.1.1 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
