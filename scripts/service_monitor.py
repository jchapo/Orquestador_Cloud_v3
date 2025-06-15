#!/usr/bin/env python3
"""
Monitor avanzado de servicios PUCP Cloud Orchestrator
"""

import subprocess
import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, List, Tuple

class PUCPServiceMonitor:
    def __init__(self):
        self.services = {
            'pucp-api-gateway': {'port': 5000, 'url': 'http://localhost/health'},
            'pucp-auth-service': {'port': 5001, 'url': 'http://localhost:5001/health'},
            'pucp-slice-service': {'port': 5002, 'url': 'http://localhost:5002/health'},
            'pucp-template-service': {'port': 5003, 'url': 'http://localhost:5003/health'},
            'pucp-network-service': {'port': 5004, 'url': 'http://localhost:5004/health'},
            'pucp-image-service': {'port': 5005, 'url': 'http://localhost:5005/health'},
        }
        
        self.results = {}
    
    def check_systemd_service(self, service_name: str) -> Dict:
        """Verifica estado de servicio systemd"""
        try:
            result = subprocess.run([
                'systemctl', 'is-active', service_name
            ], capture_output=True, text=True)
            
            is_active = result.returncode == 0
            status = result.stdout.strip()
            
            # Obtener información adicional si está activo
            if is_active:
                info_result = subprocess.run([
                    'systemctl', 'show', service_name, 
                    '--property=MainPID,ActiveEnterTimestamp,MemoryCurrent'
                ], capture_output=True, text=True)
                
                info = {}
                for line in info_result.stdout.split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        info[key] = value
                
                return {
                    'status': 'active',
                    'pid': info.get('MainPID', 'unknown'),
                    'started': info.get('ActiveEnterTimestamp', 'unknown'),
                    'memory': info.get('MemoryCurrent', 'unknown')
                }
            else:
                return {'status': status, 'error': True}
                
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def check_http_endpoint(self, url: str, timeout: int = 5) -> Dict:
        """Verifica endpoint HTTP"""
        try:
            response = requests.get(url, timeout=timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return {
                        'status': 'healthy',
                        'response_time': response.elapsed.total_seconds(),
                        'service_status': data.get('status', 'unknown'),
                        'service_name': data.get('service', 'unknown')
                    }
                except:
                    return {
                        'status': 'responding',
                        'response_time': response.elapsed.total_seconds(),
                        'http_code': response.status_code
                    }
            else:
                return {
                    'status': 'error',
                    'http_code': response.status_code,
                    'error': f'HTTP {response.status_code}'
                }
                
        except requests.exceptions.ConnectionError:
            return {'status': 'unreachable', 'error': 'Connection refused'}
        except requests.exceptions.Timeout:
            return {'status': 'timeout', 'error': 'Request timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def check_port(self, port: int) -> bool:
        """Verifica si un puerto está escuchando"""
        try:
            result = subprocess.run([
                'netstat', '-tln'
            ], capture_output=True, text=True)
            
            return f':{port} ' in result.stdout
        except:
            return False
    
    def run_full_check(self) -> Dict:
        """Ejecuta verificación completa"""
        print("🔍 Ejecutando verificación completa de servicios...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'services': {},
            'summary': {'total': 0, 'healthy': 0, 'errors': 0}
        }
        
        for service_name, config in self.services.items():
            print(f"   Verificando {service_name}...")
            
            service_result = {
                'systemd': self.check_systemd_service(service_name),
                'port': self.check_port(config['port']),
                'http': self.check_http_endpoint(config['url'])
            }
            
            # Determinar estado general
            if (service_result['systemd'].get('status') == 'active' and 
                service_result['port'] and 
                service_result['http'].get('status') == 'healthy'):
                service_result['overall_status'] = 'healthy'
                results['summary']['healthy'] += 1
            else:
                service_result['overall_status'] = 'error'
                results['summary']['errors'] += 1
            
            results['services'][service_name] = service_result
            results['summary']['total'] += 1
        
        return results
    
    def print_results(self, results: Dict):
        """Imprime resultados formateados"""
        print("\n" + "="*60)
        print("📊 REPORTE DE SERVICIOS PUCP ORCHESTRATOR")
        print("="*60)
        print(f"🕐 Timestamp: {results['timestamp']}")
        print(f"📈 Summary: {results['summary']['healthy']}/{results['summary']['total']} servicios saludables")
        
        print("\n📋 DETALLE POR SERVICIO:")
        for service_name, service_data in results['services'].items():
            status_icon = "✅" if service_data['overall_status'] == 'healthy' else "❌"
            print(f"\n{status_icon} {service_name.upper()}:")
            
            # Systemd
            systemd_status = service_data['systemd']
            if systemd_status.get('status') == 'active':
                print(f"   🔧 Systemd: Active (PID: {systemd_status.get('pid', 'unknown')})")
            else:
                print(f"   ❌ Systemd: {systemd_status.get('status', 'unknown')}")
            
            # Puerto
            port_status = "✅ Listening" if service_data['port'] else "❌ Not listening"
            print(f"   🌐 Port: {port_status}")
            
            # HTTP
            http_status = service_data['http']
            if http_status.get('status') == 'healthy':
                response_time = http_status.get('response_time', 0) * 1000
                print(f"   🏥 HTTP: Healthy ({response_time:.1f}ms)")
            else:
                print(f"   ❌ HTTP: {http_status.get('error', 'Unknown error')}")
        
        # Recomendaciones
        print(f"\n💡 RECOMENDACIONES:")
        if results['summary']['errors'] == 0:
            print("   🎉 ¡Todos los servicios están funcionando perfectamente!")
        elif results['summary']['errors'] <= 2:
            print("   ⚠️  Algunos servicios necesitan atención")
            print("   🔧 Revisar logs: sudo journalctl -u <service-name>")
        else:
            print("   🚨 Múltiples servicios con problemas")
            print("   🔄 Considerar reiniciar servicios: sudo systemctl restart pucp-*")
    
    def continuous_monitor(self, interval: int = 30):
        """Monitor continuo"""
        print(f"🔄 Iniciando monitor continuo (cada {interval}s)")
        print("Presiona Ctrl+C para detener")
        
        try:
            while True:
                results = self.run_full_check()
                
                # Solo mostrar resumen en modo continuo
                healthy = results['summary']['healthy']
                total = results['summary']['total']
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if healthy == total:
                    print(f"[{timestamp}] ✅ {healthy}/{total} servicios OK")
                else:
                    print(f"[{timestamp}] ⚠️  {healthy}/{total} servicios OK - {total-healthy} con problemas")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n👋 Monitor detenido")

def main():
    monitor = PUCPServiceMonitor()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'continuous':
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        monitor.continuous_monitor(interval)
    else:
        results = monitor.run_full_check()
        monitor.print_results(results)

if __name__ == '__main__':
    main()
