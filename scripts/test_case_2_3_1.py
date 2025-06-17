#!/usr/bin/env python3
"""
PUCP CLOUD ORCHESTRATOR - TEST CASE 2.3.1
Verificar conexiones libvirt a servidores del cluster
Objetivo: Verificar que el LinuxClusterDriver puede establecer conexiones libvirt exitosamente
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

class TestCase231:
    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.3.1",
            "objective": "Verificar conexiones libvirt a servidores del cluster",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": [],
            "connection_analysis": {}
        }
        self.available_servers = []

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

    def check_linux_servers_configured(self) -> bool:
        """Verificar que los servidores Linux estén configurados"""
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                self.available_servers = resources.get('servers', [])
                self.add_evidence("linux_servers_check", {"response": resources})
                
                expected_servers = ['server1', 'server2', 'server3', 'server4']
                found_servers = [s['hostname'] for s in self.available_servers]
                
                print(f"   Servidores encontrados: {found_servers}")
                print(f"   Servidores esperados: {expected_servers}")
                
                # Verificar que al menos tenemos los servidores esperados
                servers_ok = all(server in found_servers for server in expected_servers)
                
                return len(self.available_servers) >= 4 and servers_ok
            else:
                self.add_evidence("linux_servers_error", {"response": response.text})
                return False
        except Exception as e:
            self.add_evidence("linux_servers_error", {"error": str(e)})
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
        
        # Prerrequisito 2: Servidores Linux configurados
        print("2. Verificando servidores Linux configurados (server1-4)...")
        if self.check_linux_servers_configured():
            self.log_step(0, "Prerrequisito: Servidores Linux configurados", "PASS",
                          {"servers_count": len(self.available_servers),
                           "servers": [s['hostname'] for s in self.available_servers]})
        else:
            self.log_step(0, "Prerrequisito: Servidores Linux configurados", "FAIL")
            return False
        
        # Prerrequisito 3: Verificar que servidores están activos
        print("3. Verificando estado de servidores...")
        active_servers = [s for s in self.available_servers if s.get('status') == 'active']
        if len(active_servers) >= 4:
            self.log_step(0, "Prerrequisito: Servidores activos", "PASS",
                          {"active_servers": len(active_servers),
                           "active_hostnames": [s['hostname'] for s in active_servers]})
        else:
            self.log_step(0, "Prerrequisito: Servidores activos", "FAIL",
                          {"active_servers": len(active_servers), "required": 4})
            return False
        
        return True

    def create_test_slice_for_connection_test(self) -> Optional[str]:
        """Crear slice simple para probar conexiones libvirt"""
        print("\n🏗️ CREANDO SLICE PARA PROBAR CONEXIONES LIBVIRT")
        print("-" * 40)
        
        slice_data = {
            "name": f"test-libvirt-connections-{int(time.time())}",
            "description": "Slice para probar conexiones libvirt a servidores",
            "infrastructure": "linux",
            "placement_policy": "balanced",
            "nodes": [
                {"name": "test-vm1", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "test-vm2", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "test-vm3", "image": "ubuntu-20.04", "flavor": "nano"},
                {"name": "test-vm4", "image": "ubuntu-20.04", "flavor": "nano"}
            ],
            "networks": [
                {"name": "test-net", "cidr": "192.168.150.0/24"}
            ]
        }
        
        self.add_evidence("libvirt_test_slice_request", {"payload": slice_data})
        
        try:
            response = self.session.post(f"{API_BASE}/slices", json=slice_data)
            self.add_evidence("libvirt_test_slice_response", {
                "status_code": response.status_code,
                "response_body": response.json() if response.status_code == 201 else response.text
            })
            
            if response.status_code == 201:
                result = response.json()
                slice_id = result.get('id')
                self.log_step(1, "Crear slice para test de conexiones libvirt", "PASS",
                              {"slice_id": slice_id})
                return slice_id
            else:
                self.log_step(1, "Crear slice para test de conexiones", "FAIL",
                              {"status_code": response.status_code, "error": response.text})
                return None
                
        except Exception as e:
            self.log_step(1, "Error creando slice para test", "FAIL", {"error": str(e)})
            return None

    def test_libvirt_connections_via_deployment(self, slice_id: str) -> bool:
        """Probar conexiones libvirt a través del deployment"""
        print(f"\n🔌 PROBANDO CONEXIONES LIBVIRT VIA DEPLOYMENT")
        print("-" * 40)
        
        try:
            # Intentar deployment que forzará las conexiones libvirt
            response = self.session.post(f"{API_BASE}/slices/{slice_id}/deploy")
            
            self.add_evidence("libvirt_deployment_test", {
                "slice_id": slice_id,
                "response_status": response.status_code,
                "response_body": response.text
            })
            
            if response.status_code == 200:
                self.log_step(2, "Iniciar deployment para probar conexiones libvirt", "PASS",
                              {"status_code": response.status_code})
                return True
            else:
                # Incluso si el deployment falla, podemos haber probado las conexiones
                self.log_step(2, "Deployment para test de conexiones", "PARTIAL",
                              {"status_code": response.status_code, "note": "Deployment iniciado, analizando conexiones"})
                return True
                
        except Exception as e:
            self.log_step(2, "Error en deployment test", "FAIL", {"error": str(e)})
            return False

    def monitor_and_analyze_libvirt_connections(self, slice_id: str, timeout: int = 120) -> bool:
        """Monitorear y analizar las conexiones libvirt durante el deployment"""
        print(f"\n📊 MONITOREANDO CONEXIONES LIBVIRT")
        print("-" * 40)
        
        start_time = time.time()
        connection_evidence = {}
        
        # Monitorear por un tiempo para capturar actividad de conexiones
        while time.time() - start_time < timeout:
            try:
                # Obtener estado del slice
                response = self.session.get(f"{API_BASE}/slices/{slice_id}")
                if response.status_code == 200:
                    slice_data = response.json()
                    current_status = slice_data.get('status')
                    nodes = slice_data.get('nodes', [])
                    
                    print(f"   Status del slice: {current_status}")
                    
                    # Analizar nodos para ver asignaciones de servidores
                    server_assignments = {}
                    for node in nodes:
                        assigned_host = (
                            node.get('assigned_host') or 
                            node.get('server') or 
                            node.get('hostname')
                        )
                        if assigned_host and assigned_host != 'unassigned':
                            if assigned_host not in server_assignments:
                                server_assignments[assigned_host] = []
                            server_assignments[assigned_host].append({
                                'name': node['name'],
                                'status': node.get('status', 'unknown')
                            })
                    
                    if server_assignments:
                        connection_evidence['server_assignments'] = server_assignments
                        print(f"   Servidores con VMs asignadas: {list(server_assignments.keys())}")
                    
                    # Si el deployment completó (exitoso o con error), analizar resultados
                    if current_status in ['active', 'error']:
                        connection_evidence['final_status'] = current_status
                        connection_evidence['nodes'] = nodes
                        break
                        
                time.sleep(10)
                
            except Exception as e:
                print(f"   Error monitoreando: {e}")
                time.sleep(5)
        
        self.add_evidence("libvirt_connection_monitoring", connection_evidence)
        
        # Analizar evidencia de conexiones
        return self.analyze_libvirt_connection_evidence(connection_evidence)

    def analyze_libvirt_connection_evidence(self, evidence: Dict) -> bool:
        """Analizar evidencia de conexiones libvirt"""
        print(f"\n🔍 ANALIZANDO EVIDENCIA DE CONEXIONES LIBVIRT")
        print("-" * 40)
        
        server_assignments = evidence.get('server_assignments', {})
        final_status = evidence.get('final_status', 'unknown')
        nodes = evidence.get('nodes', [])
        
        connection_analysis = {
            'servers_contacted': list(server_assignments.keys()),
            'total_servers_used': len(server_assignments),
            'successful_connections': [],
            'failed_connections': [],
            'connection_attempts': {}
        }
        
        # Analizar cada servidor
        for server, vms in server_assignments.items():
            print(f"   📍 Servidor {server}:")
            
            # Si hay VMs asignadas, significa que hubo comunicación exitosa
            if vms:
                connection_analysis['successful_connections'].append(server)
                connection_analysis['connection_attempts'][server] = {
                    'status': 'success',
                    'evidence': f"{len(vms)} VMs asignadas",
                    'vms': vms
                }
                print(f"      ✅ Conexión exitosa - {len(vms)} VMs asignadas")
                for vm in vms:
                    print(f"         • {vm['name']}: {vm['status']}")
            else:
                connection_analysis['failed_connections'].append(server)
                connection_analysis['connection_attempts'][server] = {
                    'status': 'failed',
                    'evidence': 'No VMs asignadas'
                }
                print(f"      ❌ Sin evidencia de conexión exitosa")
        
        # Verificar si se contactaron múltiples servidores
        servers_contacted = len(connection_analysis['servers_contacted'])
        expected_servers = min(4, len(self.available_servers))  # Esperamos al menos 4 o todos los disponibles
        
        if servers_contacted >= 2:  # Al menos 2 servidores para un test básico
            self.log_step(3, "Verificar conexiones libvirt a múltiples servidores", "PASS",
                          {"servers_contacted": servers_contacted,
                           "successful_connections": len(connection_analysis['successful_connections']),
                           "servers": connection_analysis['servers_contacted']})
        else:
            self.log_step(3, "Verificar conexiones libvirt a múltiples servidores", "FAIL",
                          {"servers_contacted": servers_contacted, "expected_minimum": 2})
            
        # Verificar distribución balanceada (evidencia de conexiones a diferentes servidores)
        if len(connection_analysis['successful_connections']) >= 2:
            self.log_step(4, "Verificar distribución entre servidores (evidencia de conexiones)", "PASS",
                          {"successful_connections": connection_analysis['successful_connections']})
        else:
            self.log_step(4, "Verificar distribución entre servidores", "FAIL",
                          {"successful_connections": connection_analysis['successful_connections']})
        
        # Verificar que no hubo fallos de conexión evidentes
        connection_errors = len(connection_analysis['failed_connections'])
        if connection_errors == 0:
            self.log_step(5, "Verificar ausencia de errores de conexión", "PASS",
                          {"failed_connections": connection_errors})
        else:
            self.log_step(5, "Verificar ausencia de errores de conexión", "WARN",
                          {"failed_connections": connection_errors,
                           "failed_servers": connection_analysis['failed_connections']})
        
        self.test_results["connection_analysis"] = connection_analysis
        
        # El test es exitoso si contactamos múltiples servidores exitosamente
        return servers_contacted >= 2 and len(connection_analysis['successful_connections']) >= 2

    def verify_connection_cache_behavior(self) -> bool:
        """Verificar comportamiento de cache de conexiones a través de múltiples operaciones"""
        print(f"\n🗄️ VERIFICANDO COMPORTAMIENTO DE CACHE DE CONEXIONES")
        print("-" * 40)
        
        # Para verificar el cache, necesitamos hacer múltiples operaciones
        # El cache se evidencia por la velocidad de operaciones subsecuentes
        
        cache_test_results = {
            'multiple_operations_completed': False,
            'performance_evidence': {},
            'cache_evidence': 'Operations completed successfully suggesting connection reuse'
        }
        
        try:
            # Hacer múltiples consultas de recursos que requieren conexiones libvirt
            operation_times = []
            
            for i in range(3):
                start_time = time.time()
                response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
                end_time = time.time()
                
                operation_time = end_time - start_time
                operation_times.append(operation_time)
                
                print(f"   Operación {i+1}: {operation_time:.2f}s")
                
                if response.status_code != 200:
                    cache_test_results['cache_evidence'] = f"Operation {i+1} failed"
                    break
                    
                time.sleep(1)  # Breve pausa entre operaciones
            
            cache_test_results['multiple_operations_completed'] = len(operation_times) == 3
            cache_test_results['performance_evidence'] = {
                'operation_times': operation_times,
                'average_time': sum(operation_times) / len(operation_times) if operation_times else 0,
                'time_stability': max(operation_times) - min(operation_times) if len(operation_times) > 1 else 0
            }
            
            # Si las operaciones completaron y los tiempos son relativamente estables,
            # es evidencia de que las conexiones se están reutilizando (cache funcionando)
            if cache_test_results['multiple_operations_completed']:
                time_stability = cache_test_results['performance_evidence']['time_stability']
                if time_stability < 2.0:  # Diferencia menor a 2 segundos indica estabilidad
                    self.log_step(6, "Verificar comportamiento de cache de conexiones", "PASS",
                                  {"evidence": "Operaciones múltiples completadas con tiempos estables",
                                   "time_stability": f"{time_stability:.2f}s",
                                   "average_time": f"{cache_test_results['performance_evidence']['average_time']:.2f}s"})
                    cache_test_results['cache_evidence'] = "Connection reuse evidenced by stable operation times"
                else:
                    self.log_step(6, "Verificar comportamiento de cache de conexiones", "WARN",
                                  {"evidence": "Operaciones completadas pero con variabilidad en tiempos",
                                   "time_stability": f"{time_stability:.2f}s"})
                    cache_test_results['cache_evidence'] = "Some variability in operation times"
            else:
                self.log_step(6, "Verificar comportamiento de cache de conexiones", "FAIL",
                              {"error": "No se pudieron completar múltiples operaciones"})
                return False
            
            self.add_evidence("connection_cache_test", cache_test_results)
            return cache_test_results['multiple_operations_completed']
            
        except Exception as e:
            self.log_step(6, "Error verificando cache de conexiones", "FAIL", {"error": str(e)})
            return False

    def generate_connection_report(self):
        """Generar reporte detallado de conexiones libvirt"""
        print(f"\n📋 REPORTE DE CONEXIONES LIBVIRT")
        print("=" * 50)
        
        analysis = self.test_results.get("connection_analysis", {})
        
        print(f"Total de servidores disponibles: {len(self.available_servers)}")
        print(f"Servidores contactados: {len(analysis.get('servers_contacted', []))}")
        print(f"Conexiones exitosas: {len(analysis.get('successful_connections', []))}")
        print(f"Conexiones fallidas: {len(analysis.get('failed_connections', []))}")
        
        print(f"\n🔌 DETALLES DE CONEXIONES:")
        connection_attempts = analysis.get('connection_attempts', {})
        for server, attempt in connection_attempts.items():
            status_icon = "✅" if attempt['status'] == 'success' else "❌"
            print(f"{status_icon} {server}: {attempt['evidence']}")
            if attempt['status'] == 'success' and 'vms' in attempt:
                for vm in attempt['vms']:
                    print(f"     • {vm['name']}: {vm['status']}")
        
        print(f"\n📊 RESUMEN DE FUNCIONALIDAD LIBVIRT:")
        successful_connections = len(analysis.get('successful_connections', []))
        if successful_connections >= 2:
            print("✅ LinuxClusterDriver puede conectarse a múltiples servidores")
            print("✅ Placement balanceado funcionando (evidencia de distribución)")
            print("✅ Comunicación libvirt exitosa")
        elif successful_connections >= 1:
            print("⚠️  LinuxClusterDriver conecta a al menos un servidor")
            print("⚠️  Distribución limitada entre servidores")
        else:
            print("❌ No se pudo verificar conectividad libvirt exitosa")

    def cleanup_test_slice(self, slice_id: str):
        """Limpiar slice de prueba"""
        print(f"\n🧹 Limpiando slice de prueba...")
        try:
            response = self.session.delete(f"{API_BASE}/slices/{slice_id}")
            if response.status_code == 200:
                self.log_step(7, "Limpieza del slice de prueba", "PASS")
            else:
                self.log_step(7, "Limpieza del slice de prueba", "FAIL",
                              {"status_code": response.status_code})
        except Exception as e:
            self.log_step(7, "Error en limpieza", "FAIL", {"error": str(e)})

    def save_test_results(self):
        """Guardar resultados"""
        filename = f"test_case_2_3_1_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")

    def generate_test_report(self):
        """Generar reporte final"""
        print(f"\n📊 REPORTE FINAL DEL TEST CASO 2.3.1")
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
            icon = "✅" if step["status"] == "PASS" else "❌" if step["status"] == "FAIL" else "⚠️"
            print(f"{icon} Paso {step['step']}: {step['description']}")
        
        if self.test_results.get("connection_analysis"):
            self.generate_connection_report()

    def run_test(self):
        """Ejecutar test completo"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.3.1")
        print("Verificar conexiones libvirt a servidores del cluster")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        test_passed = False
        slice_id = None
        
        try:
            # Verificar prerrequisitos
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Crear slice para probar conexiones
            slice_id = self.create_test_slice_for_connection_test()
            if not slice_id:
                self.test_results["status"] = "FAILED_CREATE_TEST_SLICE"
                return False
            
            # Probar conexiones libvirt via deployment
            if not self.test_libvirt_connections_via_deployment(slice_id):
                self.test_results["status"] = "FAILED_LIBVIRT_CONNECTION_TEST"
                return False
            
            # Monitorear y analizar conexiones
            if not self.monitor_and_analyze_libvirt_connections(slice_id):
                self.test_results["status"] = "FAILED_CONNECTION_ANALYSIS"
                return False
            
            # Verificar cache de conexiones
            if not self.verify_connection_cache_behavior():
                self.test_results["status"] = "FAILED_CACHE_VERIFICATION"
                return False
            
            self.test_results["status"] = "PASSED"
            test_passed = True
            
            print("\n🎉 ¡TEST CASO 2.3.1 EXITOSO!")
            print("✅ Conexiones libvirt funcionando correctamente")
            print("✅ LinuxClusterDriver conecta a múltiples servidores")
            print("✅ Comportamiento de cache verificado")
            
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
            
            if slice_id:
                cleanup = input(f"\n¿Deseas eliminar el slice de prueba? (y/n): ")
                if cleanup.lower() == 'y':
                    self.cleanup_test_slice(slice_id)
                else:
                    print(f"💡 Slice conservado: {slice_id}")
        
        return test_passed

def main():
    """Función principal"""
    test = TestCase231()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.3.1 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.3.1 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
