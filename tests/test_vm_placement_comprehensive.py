#!/usr/bin/env python3
"""
PUCP Cloud Orchestrator - Plan de Pruebas Unitarias Completo
Validación integral del módulo de VM Placement y decisión de infraestructura
"""

import unittest
import json
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

# Agregar rutas del proyecto
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from slice_service.scheduler import VMScheduler
from slice_service.orchestrator import Orchestrator
from slice_service.slice_service import SliceService


class TestVMPlacementModule(unittest.TestCase):
    """
    Suite de pruebas para el módulo de VM Placement
    Validación de decisiones de infraestructura según roles y recursos
    """
    
    def setUp(self):
        """Configuración inicial para cada test"""
        self.scheduler = VMScheduler()
        self.orchestrator = Orchestrator()
        self.slice_service = SliceService()
        
        # Mock de recursos disponibles
        self.linux_resources = {
            'server1': {
                'hostname': 'pucp-server1',
                'total_vcpus': 4, 'used_vcpus': 1, 'available_vcpus': 3,
                'total_ram': 3935, 'used_ram': 512, 'available_ram': 3423,
                'total_disk': 40, 'used_disk': 10, 'available_disk': 30,
                'zone': 'student', 'infrastructure': 'linux'
            },
            'server2': {
                'hostname': 'pucp-server2', 
                'total_vcpus': 4, 'used_vcpus': 2, 'available_vcpus': 2,
                'total_ram': 3935, 'used_ram': 1024, 'available_ram': 2911,
                'total_disk': 40, 'used_disk': 15, 'available_disk': 25,
                'zone': 'student', 'infrastructure': 'linux'
            }
        }
        
        self.openstack_resources = {
            'worker1': {
                'hostname': 'worker1',
                'total_vcpus': 4, 'used_vcpus': 2, 'available_vcpus': 2,
                'total_ram': 3935, 'used_ram': 1024, 'available_ram': 2911,
                'total_disk': 40, 'used_disk': 8, 'available_disk': 32,
                'zone': 'research', 'infrastructure': 'openstack'
            },
            'worker2': {
                'hostname': 'worker2',
                'total_vcpus': 4, 'used_vcpus': 1, 'available_vcpus': 3,
                'total_ram': 3935, 'used_ram': 512, 'available_ram': 3423,
                'total_disk': 40, 'used_disk': 8, 'available_disk': 32,
                'zone': 'research', 'infrastructure': 'openstack'
            }
        }

    # ================== TESTS DE SELECCIÓN POR ROL ==================
    
    def test_student_role_placement(self):
        """
        Test 1: Verificar que usuarios con rol 'alumno' sean dirigidos a Linux
        Input: usuario "alumno" + recursos válidos
        Output esperado: backend = "linux", zona = "student"
        """
        user_profile = {
            'role': 'student',
            'username': 'alumno01',
            'preferences': {}
        }
        
        slice_config = {
            'name': 'test-slice-student',
            'vms': [
                {'name': 'vm1', 'flavor': 'small', 'image': 'ubuntu-20.04'}
            ]
        }
        
        # Mock del método de selección de infraestructura
        with patch.object(self.orchestrator, 'select_driver') as mock_select:
            mock_select.return_value = Mock()
            
            # Ejecutar decisión de placement
            result = self.orchestrator.decide_infrastructure(
                user_profile, slice_config, 'auto'
            )
            
            # Verificaciones
            self.assertEqual(result['infrastructure'], 'linux')
            self.assertEqual(result['zone'], 'student')
            self.assertTrue(result['placement_success'])
            
            # Verificar que se llamó al driver correcto
            mock_select.assert_called_with('linux')

    def test_professor_role_placement(self):
        """
        Test 2: Verificar que profesores tengan acceso a ambas infraestructuras
        Input: usuario "profesor" + modo "manual" + preferencia OpenStack
        Output esperado: backend = "openstack", zona = "research"
        """
        user_profile = {
            'role': 'professor',
            'username': 'prof01',
            'preferences': {'infrastructure': 'openstack'}
        }
        
        slice_config = {
            'name': 'test-slice-professor',
            'vms': [
                {'name': 'vm1', 'flavor': 'medium', 'image': 'ubuntu-20.04'}
            ]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'manual'
        )
        
        self.assertEqual(result['infrastructure'], 'openstack')
        self.assertEqual(result['zone'], 'research')
        self.assertTrue(result['respects_manual_selection'])

    # ================== TESTS DE MODO AUTOMÁTICO ==================
    
    def test_researcher_auto_mode(self):
        """
        Test 3: Verificar modo automático para investigadores
        Input: usuario "investigador" + modo "auto"
        Output esperado: backend = "openstack", zona = "research"
        """
        user_profile = {
            'role': 'researcher',
            'username': 'investigador01',
            'research_project': 'AI-Cloud-Computing'
        }
        
        slice_config = {
            'name': 'research-experiment',
            'vms': [
                {'name': 'gpu-node', 'flavor': 'large', 'image': 'pytorch-cuda'}
            ]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'auto'
        )
        
        self.assertEqual(result['infrastructure'], 'openstack')
        self.assertEqual(result['zone'], 'research')
        self.assertEqual(result['decision_mode'], 'auto')
        self.assertIn('resource_optimization', result)

    def test_auto_mode_resource_optimization(self):
        """
        Test 4: Verificar optimización automática de recursos
        Input: Múltiples VMs con diferentes requerimientos
        Output esperado: Distribución óptima basada en recursos disponibles
        """
        slice_config = {
            'name': 'multi-vm-slice',
            'vms': [
                {'name': 'web-server', 'flavor': 'small', 'vcpus': 1, 'ram': 512},
                {'name': 'database', 'flavor': 'medium', 'vcpus': 2, 'ram': 2048},
                {'name': 'cache', 'flavor': 'small', 'vcpus': 1, 'ram': 1024}
            ]
        }
        
        # Mock recursos disponibles
        available_resources = list(self.linux_resources.values())
        
        result = self.scheduler.schedule_slice(
            slice_config, available_resources, policy='balanced'
        )
        
        self.assertEqual(len(result['placement']), 3)
        self.assertIn('load_balancing', result)
        
        # Verificar distribución balanceada
        server_usage = {}
        for vm, placement in result['placement'].items():
            server = placement['server']
            server_usage[server] = server_usage.get(server, 0) + 1
        
        # No más de 2 VMs por servidor para balanceo
        for count in server_usage.values():
            self.assertLessEqual(count, 2)

    # ================== TESTS DE RECURSOS INSUFICIENTES ==================
    
    def test_insufficient_resources_exception(self):
        """
        Test 5: Verificar manejo de recursos insuficientes
        Input: VM requiere 32GB RAM, todos los nodos tienen <4GB
        Output esperado: Exception "InsufficientResources"
        """
        slice_config = {
            'name': 'high-memory-vm',
            'vms': [
                {'name': 'big-vm', 'flavor': 'xlarge', 'vcpus': 16, 'ram': 32768}
            ]
        }
        
        available_resources = list(self.linux_resources.values())
        
        with self.assertRaises(Exception) as context:
            self.scheduler.schedule_slice(slice_config, available_resources)
        
        self.assertIn('InsufficientResources', str(context.exception))
        self.assertIn('32768 MB RAM required', str(context.exception))

    def test_insufficient_vcpus(self):
        """
        Test 6: Verificar manejo de vCPUs insuficientes
        Input: VM requiere 8 vCPUs, máximo disponible es 4
        Output esperado: Exception con detalles específicos
        """
        slice_config = {
            'name': 'high-cpu-vm',
            'vms': [
                {'name': 'cpu-intensive', 'flavor': 'cpu-optimized', 'vcpus': 8, 'ram': 2048}
            ]
        }
        
        with self.assertRaises(Exception) as context:
            result = self.scheduler.find_placement(slice_config, self.linux_resources)
        
        self.assertIn('CPU', str(context.exception))

    # ================== TESTS DE SELECCIÓN MANUAL ==================
    
    def test_manual_selection_override(self):
        """
        Test 7: Verificar selección manual vs automática
        Input: investigador + modo "manual" + zona "student"
        Output esperado: backend = "linux", respetando selección manual
        """
        user_profile = {
            'role': 'researcher',
            'username': 'investigador02'
        }
        
        slice_config = {
            'name': 'manual-override-test',
            'infrastructure': 'linux',  # Selección manual
            'zone': 'student',
            'vms': [{'name': 'test-vm', 'flavor': 'small'}]
        }
        
        result = self.orchestrator.decide_infrastructure(
            user_profile, slice_config, 'manual'
        )
        
        self.assertEqual(result['infrastructure'], 'linux')
        self.assertEqual(result['zone'], 'student')
        self.assertTrue(result['manual_override'])
        self.assertNotEqual(result['recommended_infrastructure'], 'linux')

    # ================== TESTS DE DISTRIBUCIÓN DE CARGA ==================
    
    def test_load_distribution_sequential_vms(self):
        """
        Test 8: Verificar distribución de carga con múltiples VMs
        Input: 4 VMs secuenciales
        Output esperado: distribución balanceada entre nodos disponibles
        """
        slice_config = {
            'name': 'load-test-slice',
            'vms': [
                {'name': f'vm-{i}', 'flavor': 'small', 'vcpus': 1, 'ram': 512}
                for i in range(1, 5)
            ]
        }
        
        result = self.scheduler.schedule_slice(
            slice_config, 
            list(self.linux_resources.values()),
            policy='distributed'
        )
        
        # Verificar que las VMs se distribuyan entre servidores
        servers_used = set()
        for placement in result['placement'].values():
            servers_used.add(placement['server'])
        
        self.assertGreaterEqual(len(servers_used), 2)  # Al menos 2 servidores
        self.assertEqual(len(result['placement']), 4)  # Todas las VMs colocadas

    # ================== TESTS DE RESERVA DE RECURSOS ==================
    
    def test_resource_reservation_success(self):
        """
        Test 9: Verificar reserva de recursos
        Input: VM placement exitoso
        Output esperado: recursos marcados como reservados hasta confirmación
        """
        slice_config = {
            'name': 'reservation-test',
            'vms': [
                {'name': 'reserved-vm', 'flavor': 'medium', 'vcpus': 2, 'ram': 2048}
            ]
        }
        
        with patch.object(self.slice_service, 'reserve_resources') as mock_reserve:
            mock_reserve.return_value = {
                'reservation_id': 'res-12345',
                'expires_at': datetime.now() + timedelta(minutes=15),
                'reserved_resources': {'vcpus': 2, 'ram': 2048}
            }
            
            result = self.slice_service.create_slice_with_reservation(
                slice_config, self.linux_resources
            )
            
            self.assertTrue(result['resources_reserved'])
            self.assertIn('reservation_id', result)
            mock_reserve.assert_called_once()

    def test_resource_rollback_on_failure(self):
        """
        Test 10: Verificar rollback de recursos
        Input: fallo en creación de VM después de reserva
        Output esperado: liberación automática de recursos reservados
        """
        with patch.object(self.slice_service, 'deploy_vm') as mock_deploy:
            mock_deploy.side_effect = Exception("VM creation failed")
            
            with patch.object(self.slice_service, 'release_reservation') as mock_release:
                
                slice_config = {
                    'name': 'rollback-test',
                    'vms': [{'name': 'failing-vm', 'flavor': 'small'}]
                }
                
                with self.assertRaises(Exception):
                    self.slice_service.create_slice_with_reservation(
                        slice_config, self.linux_resources
                    )
                
                # Verificar que se liberaron los recursos
                mock_release.assert_called_once()

    # ================== TESTS DE POLÍTICAS DE PLACEMENT ==================
    
    def test_energy_efficient_placement(self):
        """
        Test 11: Verificar política de eficiencia energética
        Input: Múltiples VMs + política "energy_efficient"
        Output esperado: consolidación en servidores con mayor utilización
        """
        slice_config = {
            'name': 'energy-test',
            'vms': [
                {'name': f'vm-{i}', 'flavor': 'small', 'vcpus': 1, 'ram': 512}
                for i in range(1, 4)
            ]
        }
        
        result = self.scheduler.schedule_slice(
            slice_config,
            list(self.linux_resources.values()),
            policy='energy_efficient'
        )
        
        self.assertEqual(result['policy'], 'energy_efficient')
        # Verificar que prefiere servidores con mayor utilización
        preferred_server = max(
            self.linux_resources.values(),
            key=lambda x: x['used_vcpus'] / x['total_vcpus']
        )
        
        # Al menos una VM debe ir al servidor más utilizado
        placed_servers = [p['server'] for p in result['placement'].values()]
        self.assertIn(preferred_server['hostname'], placed_servers)

    # ================== TESTS DE VALIDACIÓN DE ENTRADAS ==================
    
    def test_invalid_slice_configuration(self):
        """
        Test 12: Verificar validación de configuraciones inválidas
        Input: Slice con configuración malformada
        Output esperado: Exception de validación
        """
        invalid_configs = [
            {'name': '', 'vms': []},  # Nombre vacío, sin VMs
            {'vms': [{'flavor': 'nonexistent'}]},  # Sin nombre de VM
            {'name': 'test', 'vms': [{'name': 'vm1'}]}  # Sin flavor
        ]
        
        for config in invalid_configs:
            with self.assertRaises(ValueError):
                self.scheduler.validate_slice_config(config)

    def test_zone_availability_validation(self):
        """
        Test 13: Verificar validación de zonas de disponibilidad
        Input: Solicitud de zona inexistente
        Output esperado: Exception o fallback a zona por defecto
        """
        slice_config = {
            'name': 'zone-test',
            'infrastructure': 'openstack',
            'zone': 'nonexistent-zone',
            'vms': [{'name': 'test-vm', 'flavor': 'small'}]
        }
        
        result = self.orchestrator.validate_and_adjust_zone(
            slice_config, self.openstack_resources
        )
        
        # Debe usar zona por defecto
        self.assertNotEqual(result['zone'], 'nonexistent-zone')
        self.assertIn(result['zone'], ['research', 'nova'])

    # ================== TESTS DE INTEGRACIÓN ==================
    
    def test_end_to_end_slice_creation(self):
        """
        Test 14: Prueba integral de creación de slice
        Input: Usuario, configuración completa, recursos disponibles
        Output esperado: Slice creado exitosamente con todas las validaciones
        """
        user_profile = {
            'role': 'student',
            'username': 'alumno_test',
            'project': 'redes-definidas'
        }
        
        slice_config = {
            'name': 'integration-test-slice',
            'description': 'Topología lineal para pruebas',
            'topology': 'linear',
            'vms': [
                {'name': 'router', 'flavor': 'small', 'image': 'ubuntu-20.04'},
                {'name': 'server', 'flavor': 'medium', 'image': 'ubuntu-20.04'},
                {'name': 'client', 'flavor': 'small', 'image': 'ubuntu-20.04'}
            ],
            'networks': [
                {'name': 'net1', 'cidr': '192.168.1.0/24'},
                {'name': 'net2', 'cidr': '192.168.2.0/24'}
            ]
        }
        
        # Mock de todos los servicios necesarios
        with patch.multiple(
            self.slice_service,
            authenticate_user=Mock(return_value=True),
            validate_permissions=Mock(return_value=True),
            check_resource_quotas=Mock(return_value=True),
            deploy_slice=Mock(return_value={'status': 'deployed', 'slice_id': 'slice-123'})
        ):
            
            result = self.slice_service.create_slice(
                user_profile, slice_config
            )
            
            self.assertEqual(result['status'], 'deployed')
            self.assertIn('slice_id', result)


class TestInfrastructureDecisionEngine(unittest.TestCase):
    """
    Tests específicos para el motor de decisión de infraestructura
    """
    
    def setUp(self):
        self.decision_engine = Orchestrator()
    
    def test_resource_based_decision(self):
        """
        Test 15: Decisión basada en recursos disponibles
        Input: Recursos limitados en Linux, abundantes en OpenStack
        Output esperado: Recomendación de OpenStack para VMs grandes
        """
        linux_limited = {
            'total_vcpus': 4, 'available_vcpus': 1,
            'total_ram': 4096, 'available_ram': 512
        }
        
        openstack_abundant = {
            'total_vcpus': 16, 'available_vcpus': 12,
            'total_ram': 32768, 'available_ram': 28672
        }
        
        large_vm_request = {
            'vms': [{'name': 'large-vm', 'vcpus': 8, 'ram': 16384}]
        }
        
        recommendation = self.decision_engine.recommend_infrastructure(
            large_vm_request, 
            {'linux': linux_limited, 'openstack': openstack_abundant}
        )
        
        self.assertEqual(recommendation['recommended'], 'openstack')
        self.assertIn('resource_availability', recommendation['reasons'])


def run_test_suite():
    """Ejecutar suite completa de pruebas"""
    
    # Configurar logging para pruebas
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Crear suite de pruebas
    test_suite = unittest.TestSuite()
    
    # Agregar todas las clases de test
    test_classes = [
        TestVMPlacementModule,
        TestInfrastructureDecisionEngine
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Ejecutar pruebas con reporte detallado
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    print("="*80)
    print("🧪 PUCP CLOUD ORCHESTRATOR - PLAN DE PRUEBAS UNITARIAS")
    print("="*80)
    print("📋 Ejecutando validación completa del módulo VM Placement...")
    print()
    
    result = runner.run(test_suite)
    
    # Reporte de resultados
    print("\n" + "="*80)
    print("📊 RESUMEN DE RESULTADOS")
    print("="*80)
    print(f"✅ Pruebas exitosas: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Pruebas fallidas: {len(result.failures)}")
    print(f"💥 Errores: {len(result.errors)}")
    print(f"⏭️  Pruebas omitidas: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print("\n🔍 DETALLES DE FALLAS:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n💥 DETALLES DE ERRORES:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_test_suite()
    sys.exit(0 if success else 1)
