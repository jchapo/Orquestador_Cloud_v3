#!/usr/bin/env python3
"""
PUCP CLOUD ORCHESTRATOR - TEST CASE 2.4.2
Verificar flujo completo de lifecycle de slice
Objetivo: Verificar que todos los endpoints del ciclo de vida de slice funcionan correctamente
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

class TestCase242:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.4.2",
            "objective": "Verificar flujo completo de lifecycle de slice",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": [],
            "lifecycle_timeline": []
        }

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

    def add_lifecycle_event(self, event_type: str, slice_status: str, details: Dict = None):
        """Agregar evento al timeline del lifecycle"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "slice_status": slice_status,
            "slice_id": self.slice_id,
            "details": details or {}
        }
        self.test_results["lifecycle_timeline"].append(event)

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

    def check_system_functioning(self) -> bool:
        """Verificar que el sistema completo está funcionando"""
        print("🔍 VERIFICANDO PRERREQUISITOS")
        print("-" * 40)
        
        # Prerrequisito 1: Autenticación
        print("1. Verificando autenticación...")
        if self.authenticate():
            self.log_step(0, "Prerrequisito: Autenticación", "PASS")
        else:
            self.log_step(0, "Prerrequisito: Autenticación", "FAIL")
            return False
        
        # Prerrequisito 2: Health check del sistema
        print("2. Verificando health del sistema...")
        try:
            response = self.session.get(f"{API_BASE}/../health")
            if response.status_code == 200:
                health_data = response.json()
                self.log_step(0, "Prerrequisito: Sistema funcionando", "PASS",
                              {"health_status": health_data.get('status')})
                self.add_evidence("system_health", health_data)
            else:
                self.log_step(0, "Prerrequisito: Sistema funcionando", "FAIL",
                              {"status_code": response.status_code})
                return False
        except Exception as e:
            self.log_step(0, "Prerrequisito: Sistema funcionando", "FAIL", {"error": str(e)})
            return False
        
        # Prerrequisito 3: Recursos disponibles
        print("3. Verificando recursos disponibles...")
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                servers = resources.get('servers', [])
                if len(servers) > 0:
                    self.log_step(0, "Prerrequisito: Recursos disponibles", "PASS",
                                  {"servers_available": len(servers)})
                else:
                    self.log_step(0, "Prerrequisito: Recursos disponibles", "FAIL",
                                  {"servers_available": 0})
                    return False
            else:
                self.log_step(0, "Prerrequisito: Recursos disponibles", "FAIL",
                              {"status_code": response.status_code})
                return False
        except Exception as e:
            self.log_step(0, "Prerrequisito: Recursos disponibles", "FAIL", {"error": str(e)})
            return False
        
        return True

    def step_1_create_slice(self) -> bool:
        """Paso 1: POST /slices (crear)"""
        print("\n🏗️ PASO 1: POST /slices (CREAR SLICE)")
        print("-" * 40)
        
        slice_data = {
            "name": f"test-lifecycle-slice-{int(time.time())}",
            "description": "Slice para probar ciclo de vida completo",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                {"name": "lifecycle-vm1", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "lifecycle-vm2", "image": "ubuntu-20.04", "flavor": "nano"}
            ],
            "networks": [
                {"name": "lifecycle-net", "cidr": "192.168.100.0/24"}
            ]
        }
        
        self.add_evidence("step_1_create_request", {
            "url": f"{API_BASE}/slices",
            "method": "POST",
            "payload": slice_data
        })
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            
            self.add_evidence("step_1_create_response", {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_body": response.json() if response.status_code == 201 else response.text
            })
            
            if response.status_code == 201:
                result = response.json()
                self.slice_id = result.get('id')
                slice_status = result.get('status', 'unknown')
                
                self.add_lifecycle_event("slice_created", slice_status, {
                    "slice_name": result.get('name'),
                    "infrastructure": result.get('infrastructure'),
                    "nodes_count": len(result.get('nodes', []))
                })
                
                self.log_step(1, "POST /slices (crear)", "PASS",
                              {"status_code": response.status_code,
                               "slice_id": self.slice_id,
                               "initial_status": slice_status})
                
                print(f"   ✅ Slice creado exitosamente")
                print(f"   🆔 ID: {self.slice_id}")
                print(f"   📊 Estado inicial: {slice_status}")
                
                return True
            else:
                self.log_step(1, "POST /slices (crear)", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(1, "Error creando slice", "FAIL", {"error": str(e)})
            return False

    def step_2_get_slice_details(self) -> bool:
        """Paso 2: GET /slices/{id} (obtener detalles)"""
        print(f"\n🔍 PASO 2: GET /slices/{self.slice_id} (OBTENER DETALLES)")
        print("-" * 40)
        
        if not self.slice_id:
            self.log_step(2, "GET /slices/{id} (obtener detalles)", "FAIL",
                          {"error": "No hay slice_id disponible"})
            return False
        
        try:
            response = self.session.get(f"{API_BASE}/slices/{self.slice_id}")
            
            self.add_evidence("step_2_get_details_response", {
                "url": f"{API_BASE}/slices/{self.slice_id}",
                "method": "GET",
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_body": response.json() if response.status_code == 200 else response.text
            })
            
            if response.status_code == 200:
                slice_data = response.json()
                slice_status = slice_data.get('status', 'unknown')
                
                self.add_lifecycle_event("slice_details_retrieved", slice_status, {
                    "nodes": slice_data.get('nodes', []),
                    "networks": slice_data.get('networks', []),
                    "resources": slice_data.get('resources', {})
                })
                
                # Verificar que los datos del slice son coherentes
                expected_fields = ['id', 'name', 'status', 'infrastructure', 'nodes', 'networks']
                missing_fields = [field for field in expected_fields if field not in slice_data]
                
                if not missing_fields:
                    self.log_step(2, "GET /slices/{id} (obtener detalles)", "PASS",
                                  {"status_code": response.status_code,
                                   "current_status": slice_status,
                                   "nodes_count": len(slice_data.get('nodes', [])),
                                   "networks_count": len(slice_data.get('networks', []))})
                    
                    print(f"   ✅ Detalles obtenidos exitosamente")
                    print(f"   📊 Estado actual: {slice_status}")
                    print(f"   🖥️ Nodos: {len(slice_data.get('nodes', []))}")
                    print(f"   🌐 Redes: {len(slice_data.get('networks', []))}")
                    
                    return True
                else:
                    self.log_step(2, "GET /slices/{id} (obtener detalles)", "FAIL",
                                  {"missing_fields": missing_fields})
                    return False
            else:
                self.log_step(2, "GET /slices/{id} (obtener detalles)", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(2, "Error obteniendo detalles", "FAIL", {"error": str(e)})
            return False

    def step_3_deploy_slice(self) -> bool:
        """Paso 3: POST /slices/{id}/deploy (desplegar)"""
        print(f"\n🚀 PASO 3: POST /slices/{self.slice_id}/deploy (DESPLEGAR)")
        print("-" * 40)
        
        if not self.slice_id:
            self.log_step(3, "POST /slices/{id}/deploy (desplegar)", "FAIL",
                          {"error": "No hay slice_id disponible"})
            return False
        
        try:
            response = self.session.post(f"{API_BASE}/slices/{self.slice_id}/deploy")
            
            self.add_evidence("step_3_deploy_response", {
                "url": f"{API_BASE}/slices/{self.slice_id}/deploy",
                "method": "POST",
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_body": response.json() if response.status_code in [200, 202] else response.text
            })
            
            if response.status_code in [200, 202]:
                result = response.json() if response.status_code == 200 else {}
                
                self.add_lifecycle_event("deployment_initiated", "deploying", {
                    "deployment_response": result
                })
                
                self.log_step(3, "POST /slices/{id}/deploy (desplegar)", "PASS",
                              {"status_code": response.status_code,
                               "deployment_initiated": True})
                
                print(f"   ✅ Deployment iniciado exitosamente")
                print(f"   📡 Código de respuesta: {response.status_code}")
                
                # Monitorear el progreso del deployment
                return self.monitor_deployment_progress()
            else:
                self.log_step(3, "POST /slices/{id}/deploy (desplegar)", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(3, "Error desplegando slice", "FAIL", {"error": str(e)})
            return False

    def monitor_deployment_progress(self, timeout: int = 180) -> bool:
        """Monitorear progreso del deployment"""
        print(f"   📊 Monitoreando progreso del deployment...")
        
        start_time = time.time()
        last_status = None
        
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(f"{API_BASE}/slices/{self.slice_id}")
                if response.status_code == 200:
                    slice_data = response.json()
                    current_status = slice_data.get('status')
                    
                    if current_status != last_status:
                        print(f"      📊 Estado: {current_status}")
                        self.add_lifecycle_event("status_change", current_status)
                        last_status = current_status
                    
                    if current_status == 'active':
                        self.add_lifecycle_event("deployment_completed", current_status, {
                            "duration": f"{time.time() - start_time:.1f}s"
                        })
                        print(f"   ✅ Deployment completado exitosamente en {time.time() - start_time:.1f}s")
                        return True
                    elif current_status == 'error':
                        error_message = slice_data.get('error_message', 'Unknown error')
                        self.add_lifecycle_event("deployment_failed", current_status, {
                            "error_message": error_message
                        })
                        print(f"   ❌ Deployment falló: {error_message}")
                        return False
                
                time.sleep(10)
                
            except Exception as e:
                print(f"      ❌ Error monitoreando: {e}")
                time.sleep(5)
        
        print(f"   ⏰ Timeout después de {timeout} segundos")
        self.add_lifecycle_event("deployment_timeout", "timeout")
        return False

    def step_4_list_slices(self) -> bool:
        """Paso 4: GET /slices (listar)"""
        print(f"\n📋 PASO 4: GET /slices (LISTAR SLICES)")
        print("-" * 40)
        
        try:
            response = self.session.get(f"{API_BASE}/slices")
            
            self.add_evidence("step_4_list_slices_response", {
                "url": f"{API_BASE}/slices",
                "method": "GET",
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_body": response.json() if response.status_code == 200 else response.text
            })
            
            if response.status_code == 200:
                slices_list = response.json()
                
                # Verificar que nuestro slice está en la lista
                our_slice_found = False
                slice_in_list = None
                
                if isinstance(slices_list, list):
                    for slice_item in slices_list:
                        if slice_item.get('id') == self.slice_id:
                            our_slice_found = True
                            slice_in_list = slice_item
                            break
                elif isinstance(slices_list, dict) and 'slices' in slices_list:
                    for slice_item in slices_list['slices']:
                        if slice_item.get('id') == self.slice_id:
                            our_slice_found = True
                            slice_in_list = slice_item
                            break
                
                self.add_lifecycle_event("slice_listed", 
                                       slice_in_list.get('status', 'unknown') if slice_in_list else 'not_found',
                                       {"found_in_list": our_slice_found, "total_slices": len(slices_list)})
                
                if our_slice_found:
                    self.log_step(4, "GET /slices (listar)", "PASS",
                                  {"status_code": response.status_code,
                                   "our_slice_found": True,
                                   "total_slices": len(slices_list),
                                   "our_slice_status": slice_in_list.get('status')})
                    
                    print(f"   ✅ Lista obtenida exitosamente")
                    print(f"   📊 Total de slices: {len(slices_list)}")
                    print(f"   🆔 Nuestro slice encontrado con estado: {slice_in_list.get('status')}")
                    
                    return True
                else:
                    self.log_step(4, "GET /slices (listar)", "FAIL",
                                  {"status_code": response.status_code,
                                   "our_slice_found": False,
                                   "total_slices": len(slices_list)})
                    return False
            else:
                self.log_step(4, "GET /slices (listar)", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(4, "Error listando slices", "FAIL", {"error": str(e)})
            return False

    def step_5_delete_slice(self) -> bool:
        """Paso 5: DELETE /slices/{id} (eliminar)"""
        print(f"\n🗑️ PASO 5: DELETE /slices/{self.slice_id} (ELIMINAR)")
        print("-" * 40)
        
        if not self.slice_id:
            self.log_step(5, "DELETE /slices/{id} (eliminar)", "FAIL",
                          {"error": "No hay slice_id disponible"})
            return False
        
        try:
            response = self.session.delete(f"{API_BASE}/slices/{self.slice_id}")
            
            self.add_evidence("step_5_delete_response", {
                "url": f"{API_BASE}/slices/{self.slice_id}",
                "method": "DELETE",
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_body": response.json() if response.status_code == 200 else response.text
            })
            
            if response.status_code == 200:
                result = response.json() if response.headers.get('content-type', '').startswith('application/json') else {"message": response.text}
                
                self.add_lifecycle_event("slice_deleted", "deleted", {
                    "deletion_response": result
                })
                
                self.log_step(5, "DELETE /slices/{id} (eliminar)", "PASS",
                              {"status_code": response.status_code,
                               "slice_deleted": True})
                
                print(f"   ✅ Slice eliminado exitosamente")
                
                # Verificar que el slice ya no existe
                return self.verify_slice_deletion()
            else:
                self.log_step(5, "DELETE /slices/{id} (eliminar)", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(5, "Error eliminando slice", "FAIL", {"error": str(e)})
            return False

    def verify_slice_deletion(self) -> bool:
        """Verificar que el slice fue eliminado"""
        print(f"   🔍 Verificando eliminación...")
        
        try:
            response = self.session.get(f"{API_BASE}/slices/{self.slice_id}")
            
            self.add_evidence("deletion_verification", {
                "url": f"{API_BASE}/slices/{self.slice_id}",
                "method": "GET",
                "status_code": response.status_code,
                "response_body": response.text
            })
            
            if response.status_code == 404:
                self.add_lifecycle_event("deletion_verified", "not_found", {
                    "verification_status": "slice_not_found_as_expected"
                })
                print(f"      ✅ Verificación exitosa: Slice no encontrado (HTTP 404)")
                return True
            else:
                print(f"      ❌ Slice aún existe (HTTP {response.status_code})")
                return False
                
        except Exception as e:
            print(f"      ❌ Error verificando eliminación: {e}")
            return False

    def generate_lifecycle_report(self):
        """Generar reporte detallado del lifecycle"""
        print(f"\n📋 REPORTE DEL CICLO DE VIDA DEL SLICE")
        print("=" * 50)
        
        timeline = self.test_results["lifecycle_timeline"]
        
        if self.slice_id:
            print(f"🆔 Slice ID: {self.slice_id}")
        
        print(f"📊 Eventos del ciclo de vida: {len(timeline)}")
        
        print(f"\n⏰ TIMELINE DE EVENTOS:")
        for i, event in enumerate(timeline, 1):
            timestamp = event['timestamp'].split('T')[1].split('.')[0]  # Solo la hora
            print(f"{i:2d}. {timestamp} | {event['event_type']:20} | Status: {event['slice_status']}")
            if event.get('details'):
                for key, value in event['details'].items():
                    if key not in ['nodes', 'networks']:  # Evitar output muy largo
                        print(f"      {key}: {value}")
        
        # Analizar transiciones de estado
        status_changes = [(e['timestamp'], e['slice_status']) for e in timeline if e['slice_status'] != 'unknown']
        
        if status_changes:
            print(f"\n📈 TRANSICIONES DE ESTADO:")
            for i, (timestamp, status) in enumerate(status_changes):
                time_str = timestamp.split('T')[1].split('.')[0]
                if i == 0:
                    print(f"   {time_str} | Estado inicial: {status}")
                else:
                    prev_status = status_changes[i-1][1]
                    if status != prev_status:
                        print(f"   {time_str} | {prev_status} → {status}")
        
        # Calcular duración total
        if len(timeline) >= 2:
            start_time = datetime.fromisoformat(timeline[0]['timestamp'])
            end_time = datetime.fromisoformat(timeline[-1]['timestamp'])
            duration = (end_time - start_time).total_seconds()
            print(f"\n⏱️ DURACIÓN TOTAL DEL CICLO: {duration:.1f} segundos")

    def save_test_results(self):
        """Guardar resultados"""
        filename = f"test_case_2_4_2_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")

    def generate_test_report(self):
        """Generar reporte final"""
        print(f"\n📊 REPORTE FINAL DEL TEST CASO 2.4.2")
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
        
        self.generate_lifecycle_report()
        
        print(f"\nEVIDENCIAS RECOLECTADAS: {len(self.test_results['evidences'])}")
        for i, evidence in enumerate(self.test_results["evidences"], 1):
            print(f"{i}. {evidence['type']} - {evidence['timestamp']}")

    def run_test(self):
        """Ejecutar test completo"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.4.2")
        print("Verificar flujo completo de lifecycle de slice")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        test_passed = False
        
        try:
            # Verificar prerrequisitos
            if not self.check_system_functioning():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Ejecutar los 5 pasos del lifecycle
            step_1 = self.step_1_create_slice()
            step_2 = self.step_2_get_slice_details() if step_1 else False
            step_3 = self.step_3_deploy_slice() if step_2 else False
            step_4 = self.step_4_list_slices() if step_3 else False
            step_5 = self.step_5_delete_slice() if step_4 else False
            
            # Evaluar si el test completo pasó
            all_steps_passed = all([step_1, step_2, step_3, step_4, step_5])
            
            if all_steps_passed:
                self.test_results["status"] = "PASSED"
                test_passed = True
                print("\n🎉 ¡TEST CASO 2.4.2 EXITOSO!")
                print("✅ Ciclo de vida completo funcionando correctamente")
                print("✅ Todos los endpoints responden apropiadamente")
                print("✅ Transiciones de estado correctas")
                print("✅ Slice creado, desplegado y eliminado exitosamente")
            else:
                self.test_results["status"] = "FAILED"
                print("\n❌ TEST CASO 2.4.2 FALLÓ")
                print("❌ Problemas en el ciclo de vida del slice")
                
                # Mostrar qué pasos fallaron
                steps_status = [
                    ("Crear slice", step_1),
                    ("Obtener detalles", step_2),
                    ("Desplegar slice", step_3),
                    ("Listar slices", step_4),
                    ("Eliminar slice", step_5)
                ]
                
                for step_name, step_result in steps_status:
                    icon = "✅" if step_result else "❌"
                    print(f"   {icon} {step_name}")
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrumpido por el usuario")
            self.test_results["status"] = "INTERRUPTED"
            
            # Intentar limpiar el slice si existe
            if self.slice_id:
                print(f"🧹 Intentando limpiar slice {self.slice_id}...")
                try:
                    self.session.delete(f"{API_BASE}/slices/{self.slice_id}")
                    print("✅ Slice limpiado")
                except:
                    print("⚠️ No se pudo limpiar automáticamente")
                    
        except Exception as e:
            print(f"\n💥 Error crítico en test: {e}")
            self.test_results["status"] = "ERROR"
        finally:
            self.test_results["end_time"] = datetime.now().isoformat()
            self.generate_test_report()
            self.save_test_results()
        
        return test_passed

def main():
    """Función principal"""
    test = TestCase242()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.4.2 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.4.2 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
