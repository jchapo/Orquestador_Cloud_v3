#!/usr/bin/env python3
"""
PUCP CLOUD ORCHESTRATOR - TEST CASE 2.2.2
Verificar manejo de escenarios sin recursos suficientes
Objetivo: Verificar que el sistema maneja apropiadamente cuando no hay recursos suficientes
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

class TestCase222:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.2.2",
            "objective": "Verificar manejo de escenarios sin recursos suficientes",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": []
        }
        self.available_servers_info = []

    def log_step(self, step_number: int, description: str, status: str, details: Dict = None):
        """Registrar un paso del test"""
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
                print(f"    {key}: {value}")

    def add_evidence(self, evidence_type: str, content: Dict):
        """Agregar evidencia"""
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

    def check_available_resources(self) -> bool:
        """Verificar recursos disponibles para calcular sobrecarga"""
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                self.available_servers_info = resources.get('servers', [])
                self.add_evidence("available_resources", {"response": resources})
                
                # Calcular recursos totales disponibles
                total_vcpus = sum(s.get('available_vcpus', 0) for s in self.available_servers_info)
                total_ram = sum(s.get('available_ram', 0) for s in self.available_servers_info)
                total_disk = sum(s.get('available_disk', 0) for s in self.available_servers_info)
                
                print(f"   Recursos totales disponibles:")
                print(f"   - vCPUs: {total_vcpus}")
                print(f"   - RAM: {total_ram} MB")
                print(f"   - Disk: {total_disk} GB")
                
                return len(self.available_servers_info) > 0
            else:
                self.add_evidence("available_resources_error", {"response": response.text})
                return False
        except Exception as e:
            self.add_evidence("available_resources_error", {"error": str(e)})
            return False

    def check_prerequisites(self) -> bool:
        """Verificar prerrequisitos"""
        print("🔍 VERIFICANDO PRERREQUISITOS")
        print("-" * 40)
        
        # Prerrequisito 1: Autenticación
        print("1. Verificando autenticación...")
        if self.authenticate():
            self.log_step(0, "Prerrequisito: Autenticación", "PASS")
        else:
            self.log_step(0, "Prerrequisito: Autenticación", "FAIL")
            return False
        
        # Prerrequisito 2: Servidores con recursos limitados
        print("2. Verificando servidores disponibles...")
        if self.check_available_resources():
            self.log_step(0, "Prerrequisito: Servidores con recursos limitados", "PASS",
                          {"servers_count": len(self.available_servers_info)})
        else:
            self.log_step(0, "Prerrequisito: Servidores disponibles", "FAIL")
            return False
        
        return True

    def create_oversized_slice(self) -> Optional[str]:
        """Crear slice que requiera más recursos que los disponibles"""
        print("\n🏗️ CREANDO SLICE QUE EXCEDE RECURSOS DISPONIBLES")
        print("-" * 40)
        
        # Calcular recursos totales disponibles
        total_vcpus = sum(s.get('available_vcpus', 0) for s in self.available_servers_info)
        total_ram = sum(s.get('available_ram', 0) for s in self.available_servers_info)
        total_disk = sum(s.get('available_disk', 0) for s in self.available_servers_info)
        
        print(f"Recursos disponibles: {total_vcpus} vCPUs, {total_ram} MB RAM, {total_disk} GB Disk")
        
        # Crear VMs que en total excedan los recursos disponibles
        # Cada servidor tiene 8 vCPUs y 16384 MB RAM
        # Vamos a crear VMs que requieran más RAM del disponible
        slice_data = {
            "name": f"test-insufficient-resources-{int(time.time())}",
            "description": "Slice que requiere más recursos que los disponibles",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                # Cada VM "large" necesita mucha RAM - vamos a crear muchas
                {"name": "vm-large-1", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-2", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-3", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-4", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-5", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-6", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-7", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                {"name": "vm-large-8", "image": "ubuntu-20.04", "flavor": "large"},  # Asumiendo ~8GB RAM
                # Total: ~64GB RAM requerido, pero solo hay ~64GB disponible
                # Agregamos más para asegurar que excedamos
                {"name": "vm-large-9", "image": "ubuntu-20.04", "flavor": "large"},
                {"name": "vm-large-10", "image": "ubuntu-20.04", "flavor": "large"}
            ],
            "networks": [
                {"name": "oversized-net", "cidr": "192.168.200.0/24"}
            ]
        }
        
        # Estimar recursos requeridos (asumiendo large = 4 vCPUs, 8192 MB RAM, 40 GB disk)
        estimated_vcpus = 10 * 4  # 40 vCPUs
        estimated_ram = 10 * 8192  # 81920 MB RAM
        estimated_disk = 10 * 40   # 400 GB disk
        
        print(f"Recursos requeridos estimados:")
        print(f"   - vCPUs: {estimated_vcpus} (disponible: {total_vcpus})")
        print(f"   - RAM: {estimated_ram} MB (disponible: {total_ram} MB)")
        print(f"   - Disk: {estimated_disk} GB (disponible: {total_disk} GB)")
        
        self.add_evidence("oversized_slice_request", {
            "payload": slice_data,
            "resource_calculation": {
                "required_vcpus": estimated_vcpus,
                "available_vcpus": total_vcpus,
                "required_ram": estimated_ram,
                "available_ram": total_ram,
                "required_disk": estimated_disk,
                "available_disk": total_disk
            }
        })
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            self.add_evidence("slice_creation_response", {
                "status_code": response.status_code,
                "response_body": response.json() if response.status_code == 201 else response.text
            })
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result.get('id')
                self.log_step(1, "Crear slice con recursos excesivos", "PASS",
                              {"slice_id": self.slice_id, "status_code": response.status_code})
                return self.slice_id
            else:
                self.log_step(1, "Crear slice con recursos excesivos", "FAIL",
                              {"status_code": response.status_code, "error": response.text})
                return None
                
        except Exception as e:
            self.log_step(1, "Error creando slice oversized", "FAIL", {"error": str(e)})
            return None

    def attempt_deployment(self, slice_id: str) -> bool:
        """Intentar deployment esperando fallo por recursos insuficientes"""
        print(f"\n🚀 INTENTANDO DEPLOYMENT (ESPERANDO FALLO)")
        print("-" * 40)
        
        try:
            response = self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            self.add_evidence("deployment_attempt", {
                "slice_id": slice_id,
                "request_url": f"{API_BASE}/slices/{slice_id}/deploy",
                "response_status": response.status_code,
                "response_body": response.text
            })
            
            if response.status_code == 500:
                # Esperamos un error 500 por recursos insuficientes
                self.log_step(2, "Intentar deployment", "PASS",
                              {"expected_failure": True, "status_code": response.status_code})
                return True
            elif response.status_code == 400:
                # También podría ser un 400 Bad Request
                error_data = response.json() if response.headers.get('content-type') == 'application/json' else {"error": response.text}
                self.log_step(2, "Intentar deployment", "PASS",
                              {"expected_failure": True, "status_code": response.status_code, "error": error_data})
                return True
            elif response.status_code == 200:
                # Si el deployment fue exitoso, es inesperado
                self.log_step(2, "Intentar deployment", "FAIL",
                              {"expected_failure": True, "actual": "deployment_succeeded", "status_code": response.status_code})
                return False
            else:
                self.log_step(2, "Intentar deployment", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(2, "Error en deployment", "FAIL", {"error": str(e)})
            return False

    def verify_appropriate_error(self, slice_id: str) -> bool:
        """Verificar que se recibió el error apropiado"""
        print(f"\n🔍 VERIFICANDO ERROR APROPIADO")
        print("-" * 40)
        
        try:
            # Verificar el estado del slice después del deployment fallido
            response = self.session.get(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                slice_data = response.json()
                slice_status = slice_data.get('status')
                error_message = slice_data.get('error_message', '')
                
                self.add_evidence("slice_status_after_failed_deployment", {
                    "slice_data": slice_data,
                    "status": slice_status,
                    "error_message": error_message
                })
                
                # Verificar que el slice está en estado de error
                if slice_status == 'error':
                    self.log_step(3, "Verificar estado de error", "PASS",
                                  {"status": slice_status, "error_message": error_message})
                    
                    # Verificar que el mensaje de error es apropiado
                    error_keywords = [
                        "insufficient", "resources", "exceeds", "limit", 
                        "not enough", "capacity", "ram", "memory", "cpu"
                    ]
                    
                    error_message_lower = error_message.lower()
                    has_appropriate_error = any(keyword in error_message_lower for keyword in error_keywords)
                    
                    if has_appropriate_error:
                        self.log_step(4, "Verificar mensaje de error específico", "PASS",
                                      {"error_message": error_message, "contains_resource_info": True})
                        return True
                    else:
                        self.log_step(4, "Verificar mensaje de error específico", "FAIL",
                                      {"error_message": error_message, "expected_keywords": error_keywords})
                        return False
                else:
                    self.log_step(3, "Verificar estado de error", "FAIL",
                                  {"expected_status": "error", "actual_status": slice_status})
                    return False
            else:
                self.log_step(3, "Obtener estado del slice", "FAIL",
                              {"status_code": response.status_code})
                return False
                
        except Exception as e:
            self.log_step(3, "Error verificando estado", "FAIL", {"error": str(e)})
            return False

    def cleanup_slice(self, slice_id: str):
        """Limpiar slice de prueba"""
        print(f"\n🧹 Limpiando slice de prueba...")
        try:
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                self.log_step(5, "Limpieza del slice", "PASS")
            else:
                self.log_step(5, "Limpieza del slice", "FAIL",
                              {"status_code": response.status_code})
        except Exception as e:
            self.log_step(5, "Error en limpieza", "FAIL", {"error": str(e)})

    def generate_test_report(self):
        """Generar reporte final"""
        print(f"\n📊 REPORTE DEL TEST CASO 2.2.2")
        print("=" * 50)
        
        passed_steps = len([s for s in self.test_results["steps"] if s["status"] == "PASS"])
        total_steps = len(self.test_results["steps"])
        
        print(f"Caso de prueba: {self.test_results['case_number']}")
        print(f"Objetivo: {self.test_results['objective']}")
        print(f"Estado final: {self.test_results['status']}")
        print(f"Pasos ejecutados: {total_steps}")
        print(f"Pasos exitosos: {passed_steps}")
        
        print(f"\nRESUMEN DE PASOS:")
        for step in self.test_results["steps"]:
            icon = "✅" if step["status"] == "PASS" else "❌"
            print(f"{icon} Paso {step['step']}: {step['description']}")
        
        print(f"\nEVIDENCIAS RECOLECTADAS: {len(self.test_results['evidences'])}")
        for i, evidence in enumerate(self.test_results["evidences"], 1):
            print(f"{i}. {evidence['type']} - {evidence['timestamp']}")

    def save_test_results(self):
        """Guardar resultados"""
        filename = f"test_case_2_2_2_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")

    def run_test(self):
        """Ejecutar test completo"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.2.2")
        print("Verificar manejo de escenarios sin recursos suficientes")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        test_passed = False
        
        try:
            # Verificar prerrequisitos
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Crear slice que requiera más recursos que los disponibles
            slice_id = self.create_oversized_slice()
            if not slice_id:
                self.test_results["status"] = "FAILED_CREATE_SLICE"
                return False
            
            # Intentar deployment (esperando fallo)
            if not self.attempt_deployment(slice_id):
                self.test_results["status"] = "FAILED_DEPLOYMENT_TEST"
                return False
            
            # Verificar error apropiado
            if self.verify_appropriate_error(slice_id):
                self.test_results["status"] = "PASSED"
                test_passed = True
                print("\n🎉 ¡TEST CASO 2.2.2 EXITOSO!")
                print("✅ Sistema maneja apropiadamente recursos insuficientes")
                print("✅ Error específico con detalles de recursos")
                print("✅ Estado de slice correctamente marcado como 'error'")
            else:
                self.test_results["status"] = "FAILED_ERROR_VERIFICATION"
                print("\n❌ TEST CASO 2.2.2 FALLÓ")
                print("❌ Error no apropiado o falta de detalles específicos")
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            self.test_results["status"] = "INTERRUPTED"
        except Exception as e:
            print(f"\n💥 Error crítico en test: {e}")
            self.test_results["status"] = "ERROR"
        finally:
            self.test_results["end_time"] = datetime.now().isoformat()
            self.generate_test_report()
            self.save_test_results()
            
            if self.slice_id:
                cleanup = input(f"\n¿Deseas eliminar el slice de prueba '{self.slice_id}'? (y/n): ")
                if cleanup.lower() == 'y':
                    self.cleanup_slice(self.slice_id)
                else:
                    print(f"💡 Slice conservado: {self.slice_id}")
        
        return test_passed

def main():
    """Función principal"""
    test = TestCase222()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.2.2 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.2.2 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
