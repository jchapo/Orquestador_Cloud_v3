#!/usr/bin/env python3
"""
Script para corregir hostnames en la base de datos
"""
import sqlite3
import os

def fix_database_hostnames():
    """Corrige hostnames inconsistentes en la base de datos"""
    
    # Ruta a la base de datos del slice service
    db_path = '/opt/pucp-orchestrator/slice_service/slice_service.db'
    
    # Si no existe, intentar otras rutas comunes
    if not os.path.exists(db_path):
        possible_paths = [
            './slice_service.db',
            '../slice_service.db',
            '/tmp/slice_service.db',
            'slice_service.db'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                db_path = path
                break
        else:
            print("❌ No se encontró la base de datos")
            return False
    
    print(f"📁 Usando base de datos: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Ver estado actual
        print("\n🔍 Estado actual de hostnames:")
        servers = conn.execute('''
            SELECT id, hostname, infrastructure 
            FROM server_resources 
            WHERE infrastructure = 'linux'
            ORDER BY hostname
        ''').fetchall()
        
        for server in servers:
            print(f"  - {server['hostname']} ({server['infrastructure']})")
        
        # Mapeo de corrección
        hostname_corrections = {
            'pucp-server1': 'server1',
            'pucp-server2': 'server2', 
            'pucp-server3': 'server3',
            'pucp-server4': 'server4'
        }
        
        corrections_made = 0
        
        # Aplicar correcciones
        for old_hostname, new_hostname in hostname_corrections.items():
            result = conn.execute('''
                UPDATE server_resources 
                SET hostname = ?, last_updated = CURRENT_TIMESTAMP
                WHERE hostname = ? AND infrastructure = 'linux'
            ''', (new_hostname, old_hostname))
            
            if result.rowcount > 0:
                print(f"✅ Corregido: {old_hostname} → {new_hostname}")
                corrections_made += 1
        
        conn.commit()
        
        # Verificar resultado
        print(f"\n📊 Correcciones realizadas: {corrections_made}")
        
        print("\n🔍 Estado después de corrección:")
        servers = conn.execute('''
            SELECT id, hostname, infrastructure 
            FROM server_resources 
            WHERE infrastructure = 'linux'
            ORDER BY hostname
        ''').fetchall()
        
        for server in servers:
            print(f"  - {server['hostname']} ({server['infrastructure']})")
        
        conn.close()
        
        print(f"\n✅ Base de datos corregida exitosamente")
        return True
        
    except Exception as e:
        print(f"❌ Error corrigiendo base de datos: {e}")
        return False

if __name__ == '__main__':
    print("🔧 Corrigiendo hostnames en base de datos...")
    success = fix_database_hostnames()
    
    if success:
        print("\n🎉 ¡Listo! Ahora el deployment debería funcionar correctamente.")
        print("💡 Reinicia el slice-service para aplicar los cambios:")
        print("   sudo systemctl restart pucp-slice-service")
    else:
        print("\n❌ Error durante la corrección. Revisa los logs.")
