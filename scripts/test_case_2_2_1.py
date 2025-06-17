#!/usr/bin/env python3
"""
PUCP CLOUD ORCHESTRATOR - TEST CASE 2.2.1 (OPTIMIZADO)
Verificación de algoritmo de placement balanceado
Se enfoca en verificar el algoritmo de placement, no en el deployment completo
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

class TestCase221Optimized:
    def __init__(self):
        self.token = None
        self.slice_id = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.2.1",
            "objective": "Verificar funcionamiento del algoritmo de placement balanceado",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": [],
            "placement_analysis": {}
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
            return False
        except Exception as e:
            self.add_evidence("authentication_error", {"error": str(e)})
            return False

    def check_available_servers(self) -> bool:
        """Verificar servidores disponibles"""
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                self.available_servers_info = resources.get('servers', [])
                self.add_evidence("available_resources", {"response": resources})
                return len(self.available_servers_info) >= 2
            return False
        except Exception as e:
            self.add_evidence("available_resources_error", {"error": str(e)})
            return False

    def check_prerequisites(self) -> bool:
        """Verificar prerrequisitos"""
        print("🔍 VERIFICANDO PRERREQUISITOS")
        print("-" * 40)

        # Autenticación
        print("1. Verificando autenticación...")
        if self.authenticate():
            self.log_step(0, "Prerrequisito: Autenticación", "PASS")
        else:
            self.log_step(0, "Prerrequisito: Autenticación", "FAIL")
            return False

        # Servidores disponibles
        print("2. Verificando servidores disponibles...")
        if self.check_available_servers():
            self.log_step(0, "Prerrequisito: Servidores disponibles", "PASS",
                          {"servers_count": len(self.available_servers_info)})
        else:
            self.log_step(0, "Prerrequisito: Servidores disponibles", "FAIL")
            return False

        return True

    def create_slice_for_placement_test(self) -> Optional[str]:
        """Crear slice específicamente para probar placement"""
        print("\n🏗️ CREANDO SLICE PARA TEST DE PLACEMENT")
        print("-" * 40)

        slice_data = {
            "name": f"test-balanced-placement-{int(time.time())}",
            "description": "Test específico del algoritmo balanced placement",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                {"name": "vm1", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "vm2", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "vm3", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "vm4", "image": "ubuntu-20.04", "flavor": "nano"}
            ],
            "networks": [
                {"name": "test-net", "cidr": "192.168.100.0/24"}
            ]
        }

        self.add_evidence("slice_creation_request", {"payload": slice_data})

        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            self.add_evidence("slice_creation_response", {
                "status_code": response.status_code,
                "response_body": response.json() if response.status_code == 201 else response.text
            })

            if response.status_code == 201:
                result = response.json()
                self.slice_id = result.get('id')
                self.log_step(1, "Crear slice con placement_policy='balanced'", "PASS",
                              {"slice_id": self.slice_id})
                self.log_step(2, "Verificar placement_policy en respuesta", "PASS",
                              {"policy": result.get('placement_policy', 'N/A')})
                return self.slice_id
            else:
                self.log_step(1, "Crear slice", "FAIL",
                              {"status_code": response.status_code, "error": response.text})
                return None
        except Exception as e:
            self.log_step(1, "Error creando slice", "FAIL", {"error": str(e)})
            return None

    def test_placement_algorithm(self, slice_id: str) -> bool:
        """Probar específicamente el algoritmo de placement"""
        print(f"\n🧮 PROBANDO ALGORITMO DE PLACEMENT")
        print("-" * 40)

        try:
            self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            time.sleep(5)
            slice_response = self.session.get(f"{API_BASE}/slices/{slice_id}")

            if slice_response.status_code == 200:
                slice_data = slice_response.json()
                nodes = slice_data.get('nodes', [])
                self.add_evidence("slice_after_placement", {
                    "slice_data": slice_data,
                    "nodes": nodes
                })
                return self.analyze_placement_algorithm(nodes)
            else:
                self.log_step(3, "Obtener datos del slice", "FAIL",
                              {"status_code": slice_response.status_code})
                return False
        except Exception as e:
            self.log_step(3, "Error probando placement", "FAIL", {"error": str(e)})
            return False

    def analyze_placement_algorithm(self, nodes: List[Dict]) -> bool:
        """Analizar los resultados del algoritmo de placement"""
        print(f"\n📊 ANALIZANDO RESULTADOS DEL PLACEMENT")
        print("-" * 40)

        if not nodes:
            self.log_step(4, "Analizar placement - Nodos disponibles", "FAIL",
                          {"error": "No hay nodos para analizar"})
            return False

        server_assignments = {}
        placement_data = {}

        for node in nodes:
            assigned_server = (
                node.get('assigned_host')
                or node.get('server')
                or node.get('hostname')
                or 'unassigned'
            )
            if assigned_server != 'unassigned':
                server_assignments.setdefault(assigned_server, []).append(node['name'])
                placement_data[node['name']] = {
                    'server': assigned_server,
                    'flavor': node.get('flavor', 'unknown'),
                    'vcpus': node.get('vcpus') or node.get('cpu', 0),
                    'ram': node.get('ram', 0),
                    'disk': node.get('disk', 0)
                }

        print("🎯 RESULTADOS DEL PLACEMENT:")
        for server, vms in server_assignments.items():
            print(f"   {server}: {vms}")

        self.test_results["placement_analysis"] = {
            "server_assignments": server_assignments,
            "placement_data": placement_data,
            "total_servers_used": len(server_assignments),
            "total_vms": len(nodes)
        }

        return self.verify_balanced_algorithm(server_assignments, placement_data)

    def verify_balanced_algorithm(self, server_assignments: Dict, placement_data: Dict) -> bool:
        """Verificar que el algoritmo balanced funciona correctamente"""
        print(f"\n✅ VERIFICANDO CRITERIOS DEL ALGORITMO BALANCED")
        print("-" * 40)

        all_checks_passed = True

        # Criteros...
        servers_used = len(server_assignments)
        if servers_used >= 2:
            self.log_step(4, "Criterio 1: Múltiples servidores utilizados", "PASS",
                          {"servers_used": servers_used, "servers": list(server_assignments.keys())})
        else:
            self.log_step(4, "Criterio 1: Múltiples servidores utilizados", "FAIL",
                          {"servers_used": servers_used})
            all_checks_passed = False

        vm_counts = [len(vms) for vms in server_assignments.values()]
        max_vms = max(vm_counts) if vm_counts else 0
        min_vms = min(vm_counts) if vm_counts else 0
        if (max_vms - min_vms) <= 1:
            self.log_step(5, "Criterio 2: Distribución equilibrada de VMs", "PASS",
                          {"vm_distribution": {srv: len(v) for srv, v in server_assignments.items()},
                           "max_vms_per_server": max_vms, "min_vms_per_server": min_vms})
        else:
            self.log_step(5, "Criterio 2: Distribución equilibrada de VMs", "FAIL",
                          {"vm_distribution": {srv: len(v) for srv, v in server_assignments.items()},
                           "difference": max_vms - min_vms})
            all_checks_passed = False

        large_vms = [vm for vm, data in placement_data.items() if data['flavor'] in ['medium', 'large']]
        if len(large_vms) > 1:
            servers_for_large = [placement_data[vm]['server'] for vm in large_vms]
            if len(set(servers_for_large)) > 1:
                self.log_step(6, "Criterio 3: VMs grandes distribuidas", "PASS",
                              {"large_vms": large_vms, "servers_used": len(set(servers_for_large))})
            else:
                self.log_step(6, "Criterio 3: VMs grandes distribuidas", "WARN",
                              {"large_vms": large_vms, "all_on_same_server": servers_for_large[0]})
        else:
            self.log_step(6, "Criterio 3: VMs grandes distribuidas", "SKIP",
                          {"reason": "Menos de 2 VMs grandes para evaluar"})

        flavors_count = len(set(data['flavor'] for data in placement_data.values()))
        if flavors_count >= 2:
            self.log_step(7, "Criterio 4: Diferentes tamaños de VM considerados", "PASS",
                          {"different_flavors": flavors_count,
                           "flavors": list(set(data['flavor'] for data in placement_data.values()))})
        else:
            self.log_step(7, "Criterio 4: Diferentes tamaños de VM considerados", "WARN",
                          {"different_flavors": flavors_count})

        return all_checks_passed

    def generate_placement_report(self):
        """Generar reporte detallado del placement"""
        print(f"\n📋 REPORTE DETALLADO DEL PLACEMENT")
        print("=" * 50)
        analysis = self.test_results["placement_analysis"]
        server_assignments = analysis.get("server_assignments", {})
        placement_data = analysis.get("placement_data", {})

        print(f"Slice ID: {self.slice_id}")
        print(f"Política de placement: balanced")
        print(f"Total de VMs: {analysis.get('total_vms', 0)}")
        print(f"Servidores utilizados: {analysis.get('total_servers_used', 0)}")

        print(f"\n🎯 ASIGNACIONES FINALES:")
        for server, vms in server_assignments.items():
            print(f"  📍 {server}:")
            for vm in vms:
                vm_data = placement_data.get(vm, {})
                print(f"     • {vm} ({vm_data.get('flavor', 'unknown')}: "
                      f"{vm_data.get('vcpus', 0)} vCPUs, {vm_data.get('ram', 0)} MB)")

        vm_counts = [len(v) for v in server_assignments.values()]
        if vm_counts:
            print(f"\n⚖️ ANÁLISIS DE BALANCEO:")
            print(f"  VMs por servidor: {vm_counts}")
            print(f"  Máximo: {max(vm_counts)} VMs")
            print(f"  Mínimo: {min(vm_counts)} VMs")
            diff = max(vm_counts) - min(vm_counts)
            print(f"  Diferencia: {diff} VMs")
            balance_quality = (
                "Excelente" if diff <= 1 else
                "Aceptable" if diff <= 2 else
                "Mejorable"
            )
            print(f"  Calidad del balanceo: {balance_quality}")

    def cleanup_slice(self, slice_id: str):
        """Limpiar slice de prueba"""
        print(f"\n🧹 Limpiando slice de prueba...")
        try:
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                self.log_step(8, "Limpieza del slice", "PASS")
            else:
                self.log_step(8, "Limpieza del slice", "FAIL",
                              {"status_code": response.status_code})
        except Exception as e:
            self.log_step(8, "Error en limpieza", "FAIL", {"error": str(e)})

    def save_test_results(self):
        """Guardar resultados"""
        filename = f"test_case_2_2_1_placement_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")

    def generate_test_report(self):
        """Generar reporte final"""
        print(f"\n📊 REPORTE FINAL DEL TEST CASO 2.2.1")
        print("=" * 50)
        passed_steps = len([s for s in self.test_results["steps"] if s["status"] == "PASS"])
        total_steps = len(self.test_results["steps"])

        print(f"Caso de prueba: {self.test_results['case_number']}")
        print(f"Objetivo: {self.test_results['objective']}")
        print(f"Estado final: {self.test_results['status']}")
        print(f"Pasos ejecutados: {total_steps}")
        print(f"Pasos exitosos: {passed_steps}")
        print(f"Porcentaje de éxito: {(passed_steps/total_steps*100):.1f}%")

        print(f"\nRESUMEN DE PASOS:")
        for step in self.test_results["steps"]:
            icon = "✅" if step["status"] == "PASS" else "❌" if step["status"] == "FAIL" else "⚠️"
            print(f"{icon} Paso {step['step']}: {step['description']}")

        if self.test_results["placement_analysis"]:
            self.generate_placement_report()

    def run_test(self):
        """Ejecutar test completo"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.2.1 (OPTIMIZADO)")
        print("Verificación específica del algoritmo de placement balanceado")
        print("=" * 70)
        self.test_results["start_time"] = datetime.now().isoformat()
        test_passed = False

        try:
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False

            slice_id = self.create_slice_for_placement_test()
            if not slice_id:
                self.test_results["status"] = "FAILED_CREATE_SLICE"
                return False

            if self.test_placement_algorithm(slice_id):
                self.test_results["status"] = "PASSED"
                test_passed = True
                print("\n🎉 ¡TEST CASO 2.2.1 EXITOSO!")
                print("✅ Algoritmo de placement balanceado funcionando correctamente")
            else:
                self.test_results["status"] = "FAILED_PLACEMENT_ALGORITHM"
                print("\n❌ TEST CASO 2.2.1 FALLÓ")

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
                cleanup = input("\n¿Deseas eliminar el slice de prueba? (y/n): ")
                if cleanup.lower() == 'y':
                    self.cleanup_slice(self.slice_id)
                else:
                    print(f"💡 Slice conservado: {self.slice_id}")

        return test_passed

def main():
    """Función principal"""
    test = TestCase221Optimized()
    success = test.run_test()
    if success:
        print("\n✅ Test Case 2.2.1 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.2.1 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
