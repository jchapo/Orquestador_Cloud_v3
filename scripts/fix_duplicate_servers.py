#!/usr/bin/env python3
"""
Script para eliminar servidores duplicados y corregir hostnames
"""
import sqlite3
import os

def fix_duplicate_servers():
    """Elimina servidores duplicados y corrige hostnames"""
    
    # Buscar base de datos
    db_path = '/opt/pucp-orchestrator/slice_service/slice_service.db'
    
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
        
        # Ver estado actual completo
        print("\n🔍 Estado actual de servidores:")
        servers = conn.execute('''
            SELECT id, hostname, infrastructure, total_vcpus, total_ram, total_disk 
            FROM server_resources 
            WHERE infrastructure = 'linux'
            ORDER BY hostname
        ''').fetchall()
        
        for server in servers:
            print(f"  - {server['hostname']} | {server['total_vcpus']} CPUs | {server['total_ram']} MB RAM | ID: {server['id'][:8]}...")
        
        print(f"\n📊 Total servidores encontrados: {len(servers)}")
        
        # ESTRATEGIA: Eliminar servidores con nombres antiguos (pucp-serverX)
        # y mantener solo los que ya tienen nombres correctos (serverX)
        
        old_hostnames = ['pucp-server1', 'pucp-server2', 'pucp-server3', 'pucp-server4']
        deleted_count = 0
        
        print(f"\n🗑️  Eliminando servidores con hostnames antiguos...")
        
        for hostname in old_hostnames:
            # Verificar si existe el servidor nuevo correspondiente
            new_hostname = hostname.replace('pucp-', '')
            
            existing_new = conn.execute('''
                SELECT id FROM server_resources 
                WHERE hostname = ? AND infrastructure = 'linux'
            ''', (new_hostname,)).fetchone()
            
            existing_old = conn.execute('''
                SELECT id FROM server_resources 
                WHERE hostname = ? AND infrastructure = 'linux'
            ''', (hostname,)).fetchone()
            
            if existing_new and existing_old:
                # Eliminar el servidor antiguo
                result = conn.execute('''
                    DELETE FROM server_resources 
                    WHERE hostname = ? AND infrastructure = 'linux'
                ''', (hostname,))
                
                if result.rowcount > 0:
                    print(f"  ✅ Eliminado: {hostname} (mantener: {new_hostname})")
                    deleted_count += 1
            elif existing_old and not existing_new:
                # Solo existe el antiguo, renombrarlo
                result = conn.execute('''
                    UPDATE server_resources 
                    SET hostname = ?, last_updated = CURRENT_TIMESTAMP
                    WHERE hostname = ? AND infrastructure = 'linux'
                ''', (new_hostname, hostname))
                
                if result.rowcount > 0:
                    print(f"  🔄 Renombrado: {hostname} → {new_hostname}")
                    deleted_count += 1
        
        conn.commit()
        
        # Verificar resultado final
        print(f"\n📊 Operaciones realizadas: {deleted_count}")
        
        print(f"\n🔍 Estado final de servidores:")
        servers = conn.execute('''
            SELECT id, hostname, infrastructure, total_vcpus, total_ram, total_disk 
            FROM server_resources 
            WHERE infrastructure = 'linux'
            ORDER BY hostname
        ''').fetchall()
        
        for server in servers:
            print(f"  - {server['hostname']} | {server['total_vcpus']} CPUs | {server['total_ram']} MB RAM")
        
        print(f"\n📊 Total servidores finales: {len(servers)}")
        
        # Verificar que tenemos exactamente 4 servidores
        expected_hostnames = ['server1', 'server2', 'server3', 'server4']
        actual_hostnames = [s['hostname'] for s in servers]
        
        missing = set(expected_hostnames) - set(actual_hostnames)
        extra = set(actual_hostnames) - set(expected_hostnames)
        
        if missing:
            print(f"⚠️  Servidores faltantes: {missing}")
        if extra:
            print(f"⚠️  Servidores extras: {extra}")
        
        if len(servers) == 4 and not missing and not extra:
            print(f"✅ ¡Perfecto! Configuración de servidores corregida")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        print(f"📋 Traceback completo:")
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("🔧 Eliminando servidores duplicados...")
    success = fix_duplicate_servers()
    
    if success:
        print(f"\n🎉 ¡Listo! Servidores duplicados eliminados.")
        print(f"💡 Reinicia el slice-service:")
        print(f"   sudo systemctl restart pucp-slice-service")
        print(f"💡 Luego prueba crear un nuevo slice.")
    else:
        print(f"\n❌ Error durante la corrección.")
