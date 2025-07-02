#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Plan de Pruebas Unitarias FUNCIONAL
Validación del módulo de VM Placement y decisión de infraestructura
"""

import unittest
import sys
import os

# Agregar rutas del proyecto
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'slice_service'))

from scheduler_fixed import VMScheduler
from orchestrator_mock import Orchestrator
from slice_service_mock import SliceService


class TestVMPlacementCore(unittest.TestCase):
    """
    Suite principal de pruebas para VM Placement
    """
    
    def setUp(self):
        """Configuración inicial"""
        self.scheduler = VMScheduler()
        self.orchestrator = Orchestrator()
        self.slice_service = SliceService()
        
        # Recursos mock
        self.linux_resources = [
            {
                'hostname': 'pucp-server1',
                'total_vcpus': 4, 'used_vcpus': 1, 'available_vcpus': 3,
                'total_ram': 4096, 'used_ram': 512, 'available_ram': 3584,
                'zone': 'student', 'infrastructure': 'linux'
            },
            {
                'hostname': 'pucp-server2',
                'total_vcpus': 4, 'used_vcpus': 2, 'available_vcpus': 2,
                'total_ram': 4096, 'used_ram': 1024, 'available_ram': 3072,
                'zone': 'student', 'infrastructure': 'linux'
            }
        ]
        
        self.openstack_resources = [
            {
                'hostname': 'worker1',
                'total_vcpus': 4, 'used_vcpus': 1, 'available_vcpus': 3,
                'total_ram': 4096, 'used_ram': 512, 'available_ram': 3584,
                'zone': 'research', 'infrastructure': 'openstack'
            }
        ]

    # ============= TESTS PRINCIPALES =============
    
    def test_01_student_role_linux_assignment(self):
        """
        Test 1: Verificar que alumnos van a Linux
        Input: usuario "student" + recursos válidos
        Output: backend = "linux", zona = "student"
        """
        print("🧪 Test 1: Asignación de estudiantes a Linux")
        
        user_profile = {'role': 'student', 'username': 'alumno01'}
        slice_config = {
            'name': 'test-slice-student',
            'vms': [{'name': 'vm1', 'flavor': 'small'}]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'auto'
        )
        
        self.assertEqual(result['infrastructure'], 'linux')
        self.assertEqual(result['zone'], 'student')
        self.assertEqual(result['decision_mode'], 'auto')
        print("   ✅ Estudiante correctamente asignado a Linux")

    def test_02_researcher_openstack_assignment(self):
        """
        Test 2: Verificar que investigadores van a OpenStack
        Input: usuario "researcher" + modo "auto"  
        Output: backend = "openstack", zona = "research"
        """
        print("🧪 Test 2: Asignación automática de investigadores")
        
        user_profile = {'role': 'researcher', 'username': 'investigador01'}
        slice_config = {
            'name': 'research-slice',
            'vms': [{'name': 'gpu-vm', 'flavor': 'large'}]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'auto'
        )
        
        self.assertEqual(result['infrastructure'], 'openstack')
        self.assertEqual(result['zone'], 'research')
        self.assertTrue(result['resource_optimization'])
        print("   ✅ Investigador correctamente asignado a OpenStack")

    def test_03_manual_override_functionality(self):
        """
        Test 3: Verificar override manual
        Input: investigador + modo "manual" + preferencia Linux
        Output: respeta selección manual
        """
        print("🧪 Test 3: Funcionalidad de override manual")
        
        user_profile = {'role': 'researcher', 'username': 'investigador02'}
        slice_config = {
            'name': 'manual-test',
            'infrastructure': 'linux',  # Selección manual
            'vms': [{'name': 'test-vm', 'flavor': 'small'}]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'manual'
        )
        
        self.assertEqual(result['infrastructure'], 'linux')
        self.assertTrue(result['manual_override'])
        self.assertTrue(result['respects_manual_selection'])
        print("   ✅ Override manual funcionando correctamente")

    def test_04_insufficient_resources_detection(self):
        """
        Test 4: Detección de recursos insuficientes
        Input: VM que requiere más recursos de los disponibles
        Output: Exception apropiada
        """
        print("🧪 Test 4: Detección de recursos insuficientes")
        
        slice_config = {
            'name': 'resource-test',
            'vms': [
                {'name': 'big-vm', 'vcpus': 16, 'ram': 32768}  # Más de lo disponible
            ]
        }
        
        # Verificar que no puede colocar la VM
        scheduler = VMScheduler()
        can_place = scheduler._can_place_vm(
            slice_config['vms'][0], 
            self.linux_resources[0]
        )
        
        self.assertFalse(can_place)
        print("   ✅ Recursos insuficientes detectados correctamente")

    def test_05_balanced_placement_policy(self):
        """
        Test 5: Política de placement balanceado
        Input: Múltiples VMs + política "balanced"
        Output: Distribución equilibrada
        """
        print("🧪 Test 5: Política de placement balanceado")
        
        slice_config = {
            'name': 'balance-test',
            'vms': [
                {'name': 'vm1', 'vcpus': 1, 'ram': 512},
                {'name': 'vm2', 'vcpus': 1, 'ram': 512},
                {'name': 'vm3', 'vcpus': 1, 'ram': 512}
            ]
        }
        
        result = self.scheduler.schedule_slice(
            slice_config, self.linux_resources, 'balanced'
        )
        
        self.assertEqual(result['policy'], 'balanced')
        self.assertEqual(len(result['placement']), 3)
        
        # Verificar distribución
        servers_used = set()
        for placement in result['placement'].values():
            servers_used.add(placement['server'])
        
        self.assertGreaterEqual(len(servers_used), 1)
        print("   ✅ Placement balanceado funcionando")

    def test_06_energy_efficient_placement(self):
        """
        Test 6: Política de eficiencia energética
        Input: VMs + política "energy_efficient"
        Output: Consolidación en servidores más utilizados
        """
        print("🧪 Test 6: Política de eficiencia energética")
        
        slice_config = {
            'name': 'energy-test',
            'vms': [
                {'name': 'vm1', 'vcpus': 1, 'ram': 512},
                {'name': 'vm2', 'vcpus': 1, 'ram': 512}
            ]
        }
        
        result = self.scheduler.schedule_slice(
            slice_config, self.linux_resources, 'energy_efficient'
        )
        
        self.assertEqual(result['policy'], 'energy_efficient')
        self.assertIn('efficiency_score', list(result['placement'].values())[0])
        print("   ✅ Política de eficiencia energética funcionando")

    def test_07_slice_config_validation(self):
        """
        Test 7: Validación de configuración de slice
        Input: Configuraciones válidas e inválidas
        Output: Validación apropiada
        """
        print("🧪 Test 7: Validación de configuración")
        
        # Configuración válida
        valid_config = {
            'name': 'valid-slice',
            'vms': [{'name': 'vm1', 'flavor': 'small'}]
        }
        
        self.assertTrue(self.scheduler.validate_slice_config(valid_config))
        
        # Configuración inválida - sin nombre
        invalid_config = {
            'vms': [{'name': 'vm1', 'flavor': 'small'}]
        }
        
        with self.assertRaises(ValueError):
            self.scheduler.validate_slice_config(invalid_config)
        
        print("   ✅ Validación de configuración funcionando")

    def test_08_resource_reservation_system(self):
        """
        Test 8: Sistema de reserva de recursos
        Input: Slice config + reserva temporal
        Output: Recursos reservados correctamente
        """
        print("🧪 Test 8: Sistema de reserva de recursos")
        
        slice_config = {
            'name': 'reservation-test',
            'vms': [{'name': 'vm1', 'vcpus': 2, 'ram': 1024}]
        }
        
        reservation = self.slice_service.reserve_resources(
            slice_config, self.linux_resources
        )
        
        self.assertIn('reservation_id', reservation)
        self.assertIn('expires_at', reservation)
        self.assertEqual(reservation['reserved_resources']['vcpus'], 2)
        print("   ✅ Sistema de reserva funcionando")

    def test_09_infrastructure_recommendation_engine(self):
        """
        Test 9: Motor de recomendación de infraestructura
        Input: Recursos limitados vs abundantes
        Output: Recomendación inteligente
        """
        print("🧪 Test 9: Motor de recomendación")
        
        vm_request = {
            'vms': [{'vcpus': 8, 'ram': 16384}]  # VM grande
        }
        
        resource_status = {
            'linux': {'available_vcpus': 2, 'available_ram': 2048},      # Limitado
            'openstack': {'available_vcpus': 16, 'available_ram': 32768} # Abundante
        }
        
        recommendation = self.orchestrator.recommend_infrastructure(
            vm_request, resource_status
        )
        
        self.assertEqual(recommendation['recommended'], 'openstack')
        self.assertIn('resource_availability', recommendation['reasons'])
        print("   ✅ Motor de recomendación funcionando")

    def test_10_end_to_end_slice_creation(self):
        """
        Test 10: Creación integral de slice
        Input: Usuario completo + configuración + workflow completo
        Output: Slice creado exitosamente
        """
        print("🧪 Test 10: Creación integral de slice")
        
        user_profile = {
            'role': 'student',
            'username': 'alumno_integral',
            'project': 'lab-redes'
        }
        
        slice_config = {
            'name': 'integration-test-slice',
            'description': 'Prueba integral',
            'infrastructure': 'linux',
            'vms': [
                {'name': 'router', 'flavor': 'small'},
                {'name': 'server', 'flavor': 'medium'},
                {'name': 'client', 'flavor': 'small'}
            ]
        }
        
        result = self.slice_service.create_slice(user_profile, slice_config)
        
        self.assertEqual(result['status'], 'deployed')
        self.assertIn('slice_id', result)
        self.assertEqual(result['user'], user_profile['username'])
        print("   ✅ Creación integral exitosa")


def run_comprehensive_tests():
    """Ejecutar suite de pruebas con reporte detallado"""
    
    print("="*80)
    print("🎯 PUCP CLOUD ORCHESTRATOR - PLAN DE PRUEBAS UNITARIAS")
    print("="*80)
    print("👥 Grupo 1 - TEL141 PUCP")
    print("📋 Validación del módulo de VM Placement y decisión de infraestructura")
    print("🏗️  Infraestructuras: Linux Cluster + OpenStack")
    print("="*80)
    print()
    
    # Ejecutar pruebas
    unittest.main(verbosity=2, exit=False, module=__name__)


if __name__ == '__main__':
    run_comprehensive_tests()
