#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Test Case 2.1.2
Caso 2.1.2 - Verificación de validación de campos requeridos y formatos
Objetivo: Verificar que la API rechaza la creación de slices con datos incompletos o inválidos
"""

import requests
import json
import time
import sys
import os
from datetime import datetime
from typing import Dict, Optional

# Configuración
API_BASE = "http://localhost/api"
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

class TestCase212:
    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.1.2",
            "objective": "Verificar que la API rechaza la creación de slices con datos incompletos o inválidos",
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
        print(f"📋 Paso {step_number}: {description} - {status}")
        if details:
            for key, value in details.items():
                print(f"   {key}: {value}")
    
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
        
        return prerequisites_ok

    def test_invalid_payload(self, step_number: int, description: str, payload: Dict, expected_error_message: Optional[str] = None) -> bool:
        """
        Envía un payload inválido y verifica la respuesta esperada.
        """
        print(f"\n{step_number}. {description} - Enviando POST /slices con payload inválido...")
        try:
            response = self.session.post(f"{API_BASE}/slices", json=payload)
            
            self.add_evidence(f"invalid_payload_request_{step_number}", {
                "url": f"{API_BASE}/slices",
                "method": "POST",
                "payload": payload,
                "response_status": response.status_code,
                "response_body": response.text
            })
            
            # Verificar respuesta HTTP 400
            if response.status_code == 400:
                self.log_step(step_number, f"{description}: Verificar HTTP 400", "PASS", 
                              {"expected": 400, "actual": response.status_code})
                
                # Opcional: Verificar mensaje de error específico
                response_data = response.json()
                if expected_error_message:
                    if expected_error_message in str(response_data): # Comprobar si el mensaje esperado está en la respuesta
                        self.log_step(step_number, f"{description}: Verificar mensaje de error", "PASS", 
                                      {"expected_contains": expected_error_message, "actual_response": response_data})
                        return True
                    else:
                        self.log_step(step_number, f"{description}: Verificar mensaje de error", "FAIL", 
                                      {"expected_contains": expected_error_message, "actual_response": response_data})
                        return False
                else:
                    return True # Pasa si solo se espera 400
            else:
                self.log_step(step_number, f"{description}: Verificar HTTP 400", "FAIL", 
                              {"expected": 400, "actual": response.status_code, "response": response.text})
                return False
                
        except requests.exceptions.ConnectionError as e:
            self.log_step(step_number, f"{description}: Error de conexión", "FAIL", {"error": str(e)})
            return False
        except json.JSONDecodeError:
            self.log_step(step_number, f"{description}: Respuesta no es JSON válido", "FAIL", {"response": response.text})
            return False
        except Exception as e:
            self.log_step(step_number, f"{description}: Error inesperado", "FAIL", {"error": str(e)})
            return False
    
    def execute_test_procedure(self) -> bool:
        """Ejecutar procedimiento del test para validaciones"""
        print("\n🧪 EJECUTANDO PROCEDIMIENTO DE PRUEBA")
        print("-" * 40)
        
        all_tests_passed = True
        step_counter = 1

        # 1. POST /slices con datos incompletos (sin 'name')
        payload_no_name = {
            "infrastructure": "linux",
            "nodes": [
                {"name": "vm1", "image": "ubuntu-20.04", "flavor": "small"}
            ],
            "networks": [
                {"name": "net1", "cidr": "192.168.1.0/24"}
            ]
        }
        if not self.test_invalid_payload(step_counter, "Slice sin nombre", payload_no_name, "name is a required field"):
            all_tests_passed = False
        step_counter += 1

        # 2. POST /slices con infraestructura inválida ("invalid")
        payload_invalid_infra = {
            "name": "test-slice-invalid-infra",
            "infrastructure": "invalid",
            "nodes": [
                {"name": "vm1", "image": "ubuntu-20.04", "flavor": "small"}
            ],
            "networks": [
                {"name": "net1", "cidr": "192.168.1.0/24"}
            ]
        }
        if not self.test_invalid_payload(step_counter, "Slice con infraestructura inválida", payload_invalid_infra, "Invalid infrastructure"):
            all_tests_passed = False
        step_counter += 1

        # 3. POST /slices con flavor inexistente ("mega")
        # Asumimos que "mega" no es un flavor válido.
        # Si tu API no valida flavors antes de la orquestación real, este test podría pasar un 201.
        # Ajusta el expected_error_message según el comportamiento real de tu API.
        payload_invalid_flavor = {
            "name": "test-slice-invalid-flavor",
            "infrastructure": "linux",
            "nodes": [
                {"name": "vm1", "image": "ubuntu-20.04", "flavor": "mega"} # "mega" no existente
            ],
            "networks": [
                {"name": "net1", "cidr": "192.168.1.0/24"}
            ]
        }
        # El mensaje de error exacto para un flavor inválido puede variar.
        # Si la API no lo valida y lo pasa a otro servicio, podrías obtener un 201
        # y el error aparecería en el estado del slice 'failed'.
        # Ajusta "Flavor 'mega' not found" si el mensaje es diferente o si no lo valida a este nivel.
        if not self.test_invalid_payload(step_counter, "Slice con flavor inexistente", payload_invalid_flavor, "Flavor 'mega' not found"):
             all_tests_passed = False
        step_counter += 1

        # 4. POST /slices sin nodos []
        payload_no_nodes = {
            "name": "test-slice-no-nodes",
            "infrastructure": "linux",
            "nodes": [], # Lista de nodos vacía
            "networks": [
                {"name": "net1", "cidr": "192.168.1.0/24"}
            ]
        }
        # Mensaje de error esperado si no se permiten slices sin nodos.
        # El orquestador puede permitir un slice sin nodos pero fallar al desplegar.
        # Ajusta el expected_error_message según el comportamiento real de tu API.
        if not self.test_invalid_payload(step_counter, "Slice sin nodos", payload_no_nodes, "nodes must contain at least 1 item"):
            all_tests_passed = False
        step_counter += 1

        return all_tests_passed
    
    def generate_test_report(self):
        """Generar reporte del test"""
        print("\n📊 REPORTE DEL TEST CASO 2.1.2")
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
            status_icon = "✅" if step["status"] == "PASS" else "❌"
            print(f"{status_icon} Paso {step['step']}: {step['description']} - {step['status']}")
        
        print(f"\nEVIDENCIAS RECOLECTADAS: {len(self.test_results['evidences'])}")
        for i, evidence in enumerate(self.test_results["evidences"], 1):
            print(f"{i}. {evidence['type']} - {evidence['timestamp']}")
            if "response_body" in evidence["content"]:
                print(f"   Response: {evidence['content']['response_body']}")
        
    def save_test_results(self):
        """Guardar resultados del test en archivo"""
        filename = f"test_case_2_1_2_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")
            
    def run_test(self):
        """Ejecutar test completo del Caso 2.1.2"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.1.2")
        print("Verificación de validación de campos requeridos y formatos")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        
        try:
            # Verificar prerrequisitos
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Ejecutar procedimiento de prueba
            if self.execute_test_procedure():
                self.test_results["status"] = "PASSED"
                print("\n🎉 ¡TEST CASO 2.1.2 EXITOSO!")
                print("✅ La API rechazó correctamente los payloads inválidos con HTTP 400")
                return True
            else:
                self.test_results["status"] = "FAILED"
                print("\n❌ TEST CASO 2.1.2 FALLÓ: Algunos escenarios de validación no se comportaron como se esperaba.")
                return False
                
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
            self.generate_test_report()
            self.save_test_results()

def main():
    """Función principal"""
    test = TestCase212()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.1.2 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.1.2 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
