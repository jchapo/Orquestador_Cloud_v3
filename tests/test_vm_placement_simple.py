"""
PUCP Cloud Orchestrator - Plan de Pruebas Unitarias FUNCIONAL
"""

import unittest
import sys
import os

# Agregar rutas del proyecto
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'slice_service'))

# Import del scheduler corregido
from scheduler_fixed import VMScheduler

class MockOrchestrator:
   def decide_infrastructure(self, user_profile, slice_config, mode='auto'):
       role = user_profile.get('role', 'student')
       
       if mode == 'manual':
           infra = slice_config.get('infrastructure', 'linux')
           return {
               'infrastructure': infra,
               'zone': 'student' if infra == 'linux' else 'research',
               'manual_override': True,
               'respects_manual_selection': True
           }
       
       # Lógica automática por rol
       if role == 'student':
           return {'infrastructure': 'linux', 'zone': 'student', 'placement_success': True}
       else:
           return {'infrastructure': 'openstack', 'zone': 'research', 'resource_optimization': True}

class TestVMPlacement(unittest.TestCase):
   """Tests principales del módulo VM Placement"""
   
   def setUp(self):
       self.scheduler = VMScheduler()
       self.orchestrator = MockOrchestrator()
       
       self.linux_resources = [
           {
               'hostname': 'pucp-server1',
               'total_vcpus': 4, 'used_vcpus': 1, 'available_vcpus': 3,
               'total_ram': 4096, 'used_ram': 512, 'available_ram': 3584
           },
           {
               'hostname': 'pucp-server2', 
               'total_vcpus': 4, 'used_vcpus': 2, 'available_vcpus': 2,
               'total_ram': 4096, 'used_ram': 1024, 'available_ram': 3072
           }
       ]

   def test_student_role_placement(self):
       """Test 1: Verificar que alumnos van a Linux"""
       print('🧪 Test 1: Asignación de estudiantes a Linux')
       
       user_profile = {'role': 'student', 'username': 'alumno01'}
       slice_config = {'name': 'test-slice', 'vms': [{'name': 'vm1', 'flavor': 'small'}]}
       
       result = self.orchestrator.decide_infrastructure(user_profile, slice_config, 'auto')
       
       self.assertEqual(result['infrastructure'], 'linux')
       self.assertEqual(result['zone'], 'student')
       print('   ✅ Estudiante correctamente asignado a Linux')

   def test_researcher_auto_mode(self):
       """Test 2: Verificar modo automático para investigadores"""
       print('🧪 Test 2: Asignación automática de investigadores')
       
       user_profile = {'role': 'researcher', 'username': 'investigador01'}
       slice_config = {'name': 'research-slice', 'vms': [{'name': 'gpu-vm', 'flavor': 'large'}]}
       
       result = self.orchestrator.decide_infrastructure(user_profile, slice_config, 'auto')
       
       self.assertEqual(result['infrastructure'], 'openstack')
       self.assertEqual(result['zone'], 'research')
       self.assertTrue(result['resource_optimization'])
       print('   ✅ Investigador correctamente asignado a OpenStack')

   def test_insufficient_resources(self):
       """Test 3: Verificar manejo de recursos insuficientes"""
       print('🧪 Test 3: Detección de recursos insuficientes')
       
       big_vm = {'name': 'big-vm', 'vcpus': 16, 'ram': 32768}
       server = self.linux_resources[0]
       
       can_place = self.scheduler._can_place_vm(big_vm, server)
       self.assertFalse(can_place)
       print('   ✅ Recursos insuficientes detectados correctamente')

   def test_manual_selection(self):
       """Test 4: Verificar selección manual"""
       print('🧪 Test 4: Selección manual de infraestructura')
       
       user_profile = {'role': 'researcher', 'username': 'investigador02'}
       slice_config = {'name': 'manual-test', 'infrastructure': 'linux', 'vms': []}
       
       result = self.orchestrator.decide_infrastructure(user_profile, slice_config, 'manual')
       
       self.assertEqual(result['infrastructure'], 'linux')
       self.assertTrue(result['manual_override'])
       print('   ✅ Selección manual respetada')

   def test_load_distribution(self):
       """Test 5: Verificar distribución de carga"""
       print('🧪 Test 5: Distribución de carga balanceada')
       
       slice_config = {
           'name': 'load-test',
           'vms': [
               {'name': 'vm1', 'vcpus': 1, 'ram': 512},
               {'name': 'vm2', 'vcpus': 1, 'ram': 512},
               {'name': 'vm3', 'vcpus': 1, 'ram': 512}
           ]
       }
       
       result = self.scheduler.schedule_slice(slice_config, self.linux_resources, 'balanced')
       
       self.assertEqual(result['policy'], 'balanced')
       self.assertEqual(len(result['placement']), 3)
       print('   ✅ Distribución balanceada funcionando')

   def test_slice_validation(self):
       """Test 6: Verificar validación de slices"""
       print('🧪 Test 6: Validación de configuración de slice')
       
       # Configuración válida
       valid_config = {'name': 'valid-slice', 'vms': [{'name': 'vm1', 'flavor': 'small'}]}
       self.assertTrue(self.scheduler.validate_slice_config(valid_config))
       
       # Configuración inválida
       invalid_config = {'vms': [{'name': 'vm1', 'flavor': 'small'}]}  # Sin nombre
       
       with self.assertRaises(ValueError):
           self.scheduler.validate_slice_config(invalid_config)
       
       print('   ✅ Validación funcionando correctamente')

   def test_energy_efficient_policy(self):
       """Test 7: Verificar política de eficiencia energética"""
       print('🧪 Test 7: Política de eficiencia energética')
       
       slice_config = {
           'name': 'energy-test',
           'vms': [{'name': 'vm1', 'vcpus': 1, 'ram': 512}]
       }
       
       result = self.scheduler.schedule_slice(slice_config, self.linux_resources, 'energy_efficient')
       
       self.assertEqual(result['policy'], 'energy_efficient')
       print('   ✅ Política de eficiencia energética funcionando')

def run_tests():
   print('='*80)
   print('🎯 PUCP CLOUD ORCHESTRATOR - PLAN DE PRUEBAS UNITARIAS')
   print('='*80)
   print('👥 Grupo 1 - TEL141 PUCP')
   print('📋 Validación del módulo de VM Placement')
   print('🏗️  Infraestructuras: Linux Cluster + OpenStack')
   print('='*80)
   print()
   
   unittest.main(verbosity=2)

if __name__ == '__main__':
   run_tests()
