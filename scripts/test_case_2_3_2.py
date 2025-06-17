#!/usr/bin/env python3
"""
PUCP CLOUD ORCHESTRATOR - TEST CASE 2.3.2
Verificar lectura de recursos reales del cluster
Objetivo: Verificar que el sistema puede leer correctamente los recursos de cada servidor
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

# Configuración esperada de recursos (basada en tu infraestructura)
EXPECTED_RESOURCES = {
    "server1": {"vcpus": 8, "ram_gb": 16, "disk_gb": 100},
    "server2": {"vcpus": 8, "ram_gb": 16, "disk_gb": 100},
    "server3": {"vcpus": 8, "ram_gb": 16, "disk_gb": 100},
    "server4": {"vcpus": 8, "ram_gb": 16, "disk_gb": 100}
}

# Tolerancias para comparación
TOLERANCE = {
    "vcpus": 0,      # Exacto
    "ram_percent": 5,  # ±5% para RAM
    "disk_percent": 10 # ±10% para disk
}

class TestCase232:
    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.test_results = {
            "case_number": "2.3.2",
            "objective": "Verificar lectura de recursos reales del cluster",
            "start_time": None,
            "end_time": None,
            "status": "PENDING",
            "steps": [],
            "evidences": [],
            "resource_analysis": {}
        }
        self.server_resources = {}

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
        
        # Prerrequisito 2: Verificar que las conexiones a servidores están establecidas
        print("2. Verificando conexiones establecidas a servidores...")
        if self.verify_server_connections():
            self.log_step(0, "Prerrequisito: Conexiones establecidas", "PASS")
        else:
            self.log_step(0, "Prerrequisito: Conexiones establecidas", "FAIL")
            return False
        
        return True

    def verify_server_connections(self) -> bool:
        """Verificar que las conexiones a servidores están establecidas"""
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            if response.status_code == 200:
                resources = response.json()
                servers = resources.get('servers', [])
                
                # Verificar que tenemos los 4 servidores esperados
                expected_servers = ['server1', 'server2', 'server3', 'server4']
                found_servers = [s['hostname'] for s in servers]
                
                print(f"   Servidores encontrados: {found_servers}")
                print(f"   Servidores esperados: {expected_servers}")
                
                # Verificar que todos los servidores están activos
                active_servers = [s for s in servers if s.get('status') == 'active']
                
                if len(active_servers) >= 4:
                    print(f"   ✅ {len(active_servers)} servidores activos")
                    return True
                else:
                    print(f"   ❌ Solo {len(active_servers)} servidores activos de 4 esperados")
                    return False
            else:
                print(f"   ❌ Error obteniendo recursos: {response.status_code}")
                return False
        except Exception as e:
            print(f"   ❌ Error verificando conexiones: {e}")
            return False

    def get_server_resources(self) -> bool:
        """Ejecutar get_server_resources() y obtener datos de recursos"""
        print("\n📊 EJECUTANDO GET_SERVER_RESOURCES()")
        print("-" * 40)
        
        try:
            response = self.session.get(f"{API_BASE}/resources?infrastructure=linux")
            
            self.add_evidence("get_server_resources_request", {
                "url": f"{API_BASE}/resources?infrastructure=linux",
                "method": "GET"
            })
            
            if response.status_code == 200:
                resources_data = response.json()
                servers = resources_data.get('servers', [])
                
                self.add_evidence("get_server_resources_response", {
                    "status_code": response.status_code,
                    "response_body": resources_data
                })
                
                # Procesar datos de cada servidor
                for server in servers:
                    hostname = server.get('hostname')
                    if hostname:
                        self.server_resources[hostname] = {
                            'hostname': hostname,
                            'total_vcpus': server.get('total_vcpus', 0),
                            'total_ram': server.get('total_ram', 0),  # En MB
                            'total_disk': server.get('total_disk', 0),  # En GB
                            'available_vcpus': server.get('available_vcpus', 0),
                            'available_ram': server.get('available_ram', 0),
                            'available_disk': server.get('available_disk', 0),
                            'used_vcpus': server.get('used_vcpus', 0),
                            'used_ram': server.get('used_ram', 0),
                            'used_disk': server.get('used_disk', 0),
                            'status': server.get('status', 'unknown'),
                            'infrastructure': server.get('infrastructure', 'unknown'),
                            'availability_zone': server.get('availability_zone', 'unknown'),
                            'zone_name': server.get('zone_name', 'unknown')
                        }
                
                self.log_step(1, "Ejecutar get_server_resources()", "PASS",
                              {"servers_found": len(servers), "response_status": response.status_code})
                
                print(f"   Servidores procesados: {list(self.server_resources.keys())}")
                return True
            else:
                self.log_step(1, "Ejecutar get_server_resources()", "FAIL",
                              {"status_code": response.status_code, "response": response.text})
                return False
                
        except Exception as e:
            self.log_step(1, "Error ejecutando get_server_resources()", "FAIL", {"error": str(e)})
            return False

    def verify_cpu_ram_disk_data(self) -> bool:
        """Verificar datos de CPU, RAM, disk para cada servidor"""
        print("\n🔍 VERIFICANDO DATOS DE CPU, RAM, DISK")
        print("-" * 40)
        
        if not self.server_resources:
            self.log_step(2, "Verificar datos de recursos", "FAIL",
                          {"error": "No hay datos de recursos para verificar"})
            return False
        
        verification_results = {}
        all_servers_ok = True
        
        for hostname, resources in self.server_resources.items():
            print(f"\n   📍 Verificando {hostname}:")
            
            server_verification = {
                'hostname': hostname,
                'vcpus_check': False,
                'ram_check': False,
                'disk_check': False,
                'data_completeness': False,
                'issues': []
            }
            
            # Verificar vCPUs
            total_vcpus = resources.get('total_vcpus', 0)
            expected_vcpus = EXPECTED_RESOURCES.get(hostname, {}).get('vcpus', 8)
            
            if total_vcpus == expected_vcpus:
                server_verification['vcpus_check'] = True
                print(f"      ✅ vCPUs: {total_vcpus} (esperado: {expected_vcpus})")
            else:
                server_verification['issues'].append(f"vCPUs: {total_vcpus} vs esperado {expected_vcpus}")
                print(f"      ❌ vCPUs: {total_vcpus} (esperado: {expected_vcpus})")
                all_servers_ok = False
            
            # Verificar RAM (convertir MB a GB para comparación)
            total_ram_mb = resources.get('total_ram', 0)
            total_ram_gb = total_ram_mb / 1024 if total_ram_mb > 0 else 0
            expected_ram_gb = EXPECTED_RESOURCES.get(hostname, {}).get('ram_gb', 16)
            
            ram_tolerance = expected_ram_gb * (TOLERANCE['ram_percent'] / 100)
            ram_diff = abs(total_ram_gb - expected_ram_gb)
            
            if ram_diff <= ram_tolerance:
                server_verification['ram_check'] = True
                print(f"      ✅ RAM: {total_ram_gb:.1f} GB ({total_ram_mb} MB) (esperado: ~{expected_ram_gb} GB)")
            else:
                server_verification['issues'].append(f"RAM: {total_ram_gb:.1f} GB vs esperado ~{expected_ram_gb} GB")
                print(f"      ❌ RAM: {total_ram_gb:.1f} GB (esperado: ~{expected_ram_gb} GB, tolerancia: ±{TOLERANCE['ram_percent']}%)")
                all_servers_ok = False
            
            # Verificar Disk
            total_disk_gb = resources.get('total_disk', 0)
            expected_disk_gb = EXPECTED_RESOURCES.get(hostname, {}).get('disk_gb', 100)
            
            disk_tolerance = expected_disk_gb * (TOLERANCE['disk_percent'] / 100)
            disk_diff = abs(total_disk_gb - expected_disk_gb)
            
            if disk_diff <= disk_tolerance:
                server_verification['disk_check'] = True
                print(f"      ✅ Disk: {total_disk_gb} GB (esperado: ~{expected_disk_gb} GB)")
            else:
                server_verification['issues'].append(f"Disk: {total_disk_gb} GB vs esperado ~{expected_disk_gb} GB")
                print(f"      ❌ Disk: {total_disk_gb} GB (esperado: ~{expected_disk_gb} GB, tolerancia: ±{TOLERANCE['disk_percent']}%)")
                all_servers_ok = False
            
            # Verificar completitud de datos
            required_fields = ['total_vcpus', 'total_ram', 'total_disk', 'available_vcpus', 'available_ram', 'available_disk']
            missing_fields = [field for field in required_fields if resources.get(field) is None]
            
            if not missing_fields:
                server_verification['data_completeness'] = True
                print(f"      ✅ Completitud de datos: Todos los campos presentes")
            else:
                server_verification['issues'].append(f"Campos faltantes: {missing_fields}")
                print(f"      ❌ Campos faltantes: {missing_fields}")
                all_servers_ok = False
            
            verification_results[hostname] = server_verification
        
        self.add_evidence("resource_verification", verification_results)
        
        if all_servers_ok:
            self.log_step(2, "Verificar datos de CPU, RAM, disk", "PASS",
                          {"servers_verified": len(verification_results),
                           "all_checks_passed": True})
        else:
            failed_servers = [h for h, v in verification_results.items() if v['issues']]
            self.log_step(2, "Verificar datos de CPU, RAM, disk", "FAIL",
                          {"servers_with_issues": failed_servers,
                           "total_servers": len(verification_results)})
        
        return all_servers_ok

    def compare_with_expected_configuration(self) -> bool:
        """Comparar con configuración esperada"""
        print("\n⚖️ COMPARANDO CON CONFIGURACIÓN ESPERADA")
        print("-" * 40)
        
        comparison_results = {}
        all_comparisons_ok = True
        
        for hostname, expected in EXPECTED_RESOURCES.items():
            if hostname in self.server_resources:
                actual = self.server_resources[hostname]
                
                comparison = {
                    'hostname': hostname,
                    'vcpus': {
                        'expected': expected['vcpus'],
                        'actual': actual.get('total_vcpus', 0),
                        'match': actual.get('total_vcpus', 0) == expected['vcpus']
                    },
                    'ram_gb': {
                        'expected': expected['ram_gb'],
                        'actual': round(actual.get('total_ram', 0) / 1024, 1),
                        'match': abs((actual.get('total_ram', 0) / 1024) - expected['ram_gb']) <= (expected['ram_gb'] * 0.05)
                    },
                    'disk_gb': {
                        'expected': expected['disk_gb'],
                        'actual': actual.get('total_disk', 0),
                        'match': abs(actual.get('total_disk', 0) - expected['disk_gb']) <= (expected['disk_gb'] * 0.1)
                    }
                }
                
                # Verificar si todas las comparaciones son exitosas
                server_ok = all([
                    comparison['vcpus']['match'],
                    comparison['ram_gb']['match'],
                    comparison['disk_gb']['match']
                ])
                
                if not server_ok:
                    all_comparisons_ok = False
                
                comparison['overall_match'] = server_ok
                comparison_results[hostname] = comparison
                
                print(f"   📍 {hostname}:")
                print(f"      vCPUs: {comparison['vcpus']['actual']} vs {comparison['vcpus']['expected']} {'✅' if comparison['vcpus']['match'] else '❌'}")
                print(f"      RAM: {comparison['ram_gb']['actual']} GB vs {comparison['ram_gb']['expected']} GB {'✅' if comparison['ram_gb']['match'] else '❌'}")
                print(f"      Disk: {comparison['disk_gb']['actual']} GB vs {comparison['disk_gb']['expected']} GB {'✅' if comparison['disk_gb']['match'] else '❌'}")
            else:
                print(f"   ❌ {hostname}: No encontrado en recursos obtenidos")
                all_comparisons_ok = False
        
        self.add_evidence("configuration_comparison", comparison_results)
        
        if all_comparisons_ok:
            self.log_step(3, "Comparar con configuración esperada", "PASS",
                          {"servers_compared": len(comparison_results),
                           "all_matches": True})
        else:
            mismatched_servers = [h for h, c in comparison_results.items() if not c.get('overall_match', False)]
            self.log_step(3, "Comparar con configuración esperada", "FAIL",
                          {"mismatched_servers": mismatched_servers})
        
        return all_comparisons_ok

    def validate_response_format(self) -> bool:
        """Validar formato de response"""
        print("\n📋 VALIDANDO FORMATO DE RESPONSE")
        print("-" * 40)
        
        format_validation = {
            'json_structure_valid': True,
            'required_fields_present': True,
            'data_types_correct': True,
            'issues': []
        }
        
        # Verificar estructura JSON básica
        if not self.server_resources:
            format_validation['json_structure_valid'] = False
            format_validation['issues'].append("No se obtuvieron datos de recursos")
        
        # Verificar campos requeridos para cada servidor
        required_server_fields = [
            'hostname', 'total_vcpus', 'total_ram', 'total_disk',
            'available_vcpus', 'available_ram', 'available_disk',
            'status', 'infrastructure'
        ]
        
        for hostname, server_data in self.server_resources.items():
            missing_fields = []
            wrong_types = []
            
            for field in required_server_fields:
                if field not in server_data or server_data[field] is None:
                    missing_fields.append(field)
                else:
                    # Verificar tipos de datos
                    if field == 'hostname' and not isinstance(server_data[field], str):
                        wrong_types.append(f"{field}: expected str, got {type(server_data[field])}")
                    elif field in ['total_vcpus', 'total_ram', 'total_disk', 'available_vcpus', 'available_ram', 'available_disk'] and not isinstance(server_data[field], (int, float)):
                        wrong_types.append(f"{field}: expected number, got {type(server_data[field])}")
            
            if missing_fields:
                format_validation['required_fields_present'] = False
                format_validation['issues'].append(f"{hostname}: Missing fields {missing_fields}")
            
            if wrong_types:
                format_validation['data_types_correct'] = False
                format_validation['issues'].append(f"{hostname}: Wrong types {wrong_types}")
        
        # Verificar rangos lógicos
        for hostname, server_data in self.server_resources.items():
            # available <= total
            if server_data.get('available_vcpus', 0) > server_data.get('total_vcpus', 0):
                format_validation['issues'].append(f"{hostname}: available_vcpus > total_vcpus")
            if server_data.get('available_ram', 0) > server_data.get('total_ram', 0):
                format_validation['issues'].append(f"{hostname}: available_ram > total_ram")
            if server_data.get('available_disk', 0) > server_data.get('total_disk', 0):
                format_validation['issues'].append(f"{hostname}: available_disk > total_disk")
        
        self.add_evidence("response_format_validation", format_validation)
        
        format_ok = (format_validation['json_structure_valid'] and 
                    format_validation['required_fields_present'] and 
                    format_validation['data_types_correct'] and 
                    len(format_validation['issues']) == 0)
        
        if format_ok:
            self.log_step(4, "Validar formato de response", "PASS",
                          {"servers_validated": len(self.server_resources),
                           "format_issues": 0})
            print("   ✅ Estructura JSON válida")
            print("   ✅ Todos los campos requeridos presentes")
            print("   ✅ Tipos de datos correctos")
            print("   ✅ Rangos lógicos válidos")
        else:
            self.log_step(4, "Validar formato de response", "FAIL",
                          {"format_issues": len(format_validation['issues']),
                           "issues": format_validation['issues']})
            print(f"   ❌ {len(format_validation['issues'])} problemas de formato encontrados")
            for issue in format_validation['issues']:
                print(f"      • {issue}")
        
        return format_ok

    def generate_resource_report(self):
        """Generar reporte detallado de recursos"""
        print(f"\n📋 REPORTE DETALLADO DE RECURSOS DEL CLUSTER")
        print("=" * 60)
        
        print(f"Total de servidores analizados: {len(self.server_resources)}")
        
        print(f"\n📊 RECURSOS POR SERVIDOR:")
        for hostname, resources in self.server_resources.items():
            print(f"\n🖥️  {hostname.upper()}:")
            print(f"   • Status: {resources.get('status', 'unknown')}")
            print(f"   • Zona: {resources.get('zone_name', 'unknown')}")
            print(f"   • vCPUs: {resources.get('total_vcpus', 0)} total, {resources.get('available_vcpus', 0)} disponibles")
            print(f"   • RAM: {resources.get('total_ram', 0)} MB total ({resources.get('total_ram', 0)/1024:.1f} GB), {resources.get('available_ram', 0)} MB disponibles")
            print(f"   • Disk: {resources.get('total_disk', 0)} GB total, {resources.get('available_disk', 0)} GB disponibles")
            
            # Calcular utilización
            vcpu_usage = ((resources.get('total_vcpus', 0) - resources.get('available_vcpus', 0)) / resources.get('total_vcpus', 1)) * 100
            ram_usage = ((resources.get('total_ram', 0) - resources.get('available_ram', 0)) / resources.get('total_ram', 1)) * 100
            disk_usage = ((resources.get('total_disk', 0) - resources.get('available_disk', 0)) / resources.get('total_disk', 1)) * 100
            
            print(f"   • Utilización: CPU {vcpu_usage:.1f}%, RAM {ram_usage:.1f}%, Disk {disk_usage:.1f}%")
        
        # Resumen del cluster
        total_vcpus = sum(r.get('total_vcpus', 0) for r in self.server_resources.values())
        total_ram_gb = sum(r.get('total_ram', 0) for r in self.server_resources.values()) / 1024
        total_disk_gb = sum(r.get('total_disk', 0) for r in self.server_resources.values())
        
        available_vcpus = sum(r.get('available_vcpus', 0) for r in self.server_resources.values())
        available_ram_gb = sum(r.get('available_ram', 0) for r in self.server_resources.values()) / 1024
        available_disk_gb = sum(r.get('available_disk', 0) for r in self.server_resources.values())
        
        print(f"\n📈 RESUMEN DEL CLUSTER:")
        print(f"   • Total vCPUs: {total_vcpus} ({available_vcpus} disponibles)")
        print(f"   • Total RAM: {total_ram_gb:.1f} GB ({available_ram_gb:.1f} GB disponibles)")
        print(f"   • Total Disk: {total_disk_gb} GB ({available_disk_gb} GB disponibles)")

    def save_test_results(self):
        """Guardar resultados"""
        filename = f"test_case_2_3_2_results_{int(time.time())}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.test_results, f, indent=2)
            print(f"\n💾 Resultados guardados en: {filename}")
        except Exception as e:
            print(f"❌ Error guardando resultados: {e}")

    def generate_test_report(self):
        """Generar reporte final"""
        print(f"\n📊 REPORTE FINAL DEL TEST CASO 2.3.2")
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
        
        if self.server_resources:
            self.generate_resource_report()

    def run_test(self):
        """Ejecutar test completo"""
        print("🧪 PUCP CLOUD ORCHESTRATOR - TEST CASE 2.3.2")
        print("Verificar lectura de recursos reales del cluster")
        print("=" * 60)
        
        self.test_results["start_time"] = datetime.now().isoformat()
        test_passed = False
        
        try:
            # Verificar prerrequisitos
            if not self.check_prerequisites():
                self.test_results["status"] = "FAILED_PREREQUISITES"
                return False
            
            # Ejecutar get_server_resources()
            if not self.get_server_resources():
                self.test_results["status"] = "FAILED_GET_RESOURCES"
                return False
            
            # Verificar datos de CPU, RAM, disk
            resources_ok = self.verify_cpu_ram_disk_data()
            
            # Comparar con configuración esperada
            config_ok = self.compare_with_expected_configuration()
            
            # Validar formato de response
            format_ok = self.validate_response_format()
            
            # El test es exitoso si al menos los recursos se leen correctamente y el formato es válido
            if resources_ok and format_ok:
                self.test_results["status"] = "PASSED"
                test_passed = True
                print("\n🎉 ¡TEST CASO 2.3.2 EXITOSO!")
                print("✅ Lectura de recursos del cluster funcionando")
                print("✅ Datos de CPU, RAM, disk verificados")
                print("✅ Formato de response válido")
                if config_ok:
                    print("✅ Configuración coincide con lo esperado")
                else:
                    print("⚠️  Algunas diferencias con configuración esperada")
            else:
                self.test_results["status"] = "FAILED"
                print("\n❌ TEST CASO 2.3.2 FALLÓ")
                if not resources_ok:
                    print("❌ Problemas con datos de recursos")
                if not format_ok:
                    print("❌ Problemas con formato de response")
            
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
        
        return test_passed

def main():
    """Función principal"""
    test = TestCase232()
    success = test.run_test()
    
    if success:
        print("\n✅ Test Case 2.3.2 completado exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Test Case 2.3.2 falló")
        sys.exit(1)

if __name__ == '__main__':
    main()
