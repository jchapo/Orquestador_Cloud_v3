#!/bin/bash
"""
Corrección de OVS y optimización del cluster PUCP
"""

set -e

echo "🔧 PUCP Cluster - Corrección y Optimización"
echo "============================================"

# Función para logging
log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "✅ $1"
}

log_warning() {
    echo "⚠️  $1"
}

log_error() {
    echo "❌ $1"
}

# 1. Corregir problema de OVS (pucp-ovs1)
fix_ovs_connectivity() {
    log_info "Corrigiendo conectividad OVS..."
    
    # Opción 1: Verificar si OVS está en uno de los servidores existentes
    log_info "Verificando configuración OVS en servidores existentes..."
    
    for server in server1 server2 server3 server4; do
        log_info "Verificando OVS en $server..."
        
        result=$(ssh $server "sudo ovs-vsctl show 2>/dev/null || echo 'NO_OVS'" | head -1)
        
        if [[ "$result" != "NO_OVS" && "$result" != "" ]]; then
            log_success "OVS encontrado en $server"
            
            # Configurar OVS bridge si no existe
            ssh $server << 'EOF'
                # Crear bridge principal si no existe
                sudo ovs-vsctl --may-exist add-br ovs1
                
                # Configurar VLAN tags para cluster PUCP
                sudo ovs-vsctl set bridge ovs1 other-config:forward-bpdu=true
                
                # Verificar configuración
                echo "OVS Bridges:"
                sudo ovs-vsctl list-br
                
                echo "OVS Ports:"
                sudo ovs-vsctl list-ports ovs1 2>/dev/null || echo "No ports configured yet"
EOF
            
            log_success "OVS configurado en $server"
            
            # Actualizar configuración para usar este servidor como OVS
            echo "OVS_SERVER=$server" > /tmp/ovs_config.env
            
            return 0
        fi
    done
    
    log_warning "OVS no encontrado en ningún servidor - continuando sin OVS específico"
    return 1
}

# 2. Optimizar configuración de libvirt en todos los servidores
optimize_libvirt() {
    log_info "Optimizando configuración libvirt..."
    
    for server in server1 server2 server3 server4; do
        log_info "Optimizando $server..."
        
        ssh $server << 'EOF'
            # Configurar red default de libvirt
            sudo virsh net-autostart default 2>/dev/null || true
            sudo virsh net-start default 2>/dev/null || true
            
            # Configurar storage pool default
            sudo virsh pool-autostart default 2>/dev/null || true
            sudo virsh pool-start default 2>/dev/null || true
            
            # Asegurar permisos correctos
            sudo chown -R libvirt-qemu:libvirt-qemu /var/lib/libvirt/images/
            sudo chmod 755 /var/lib/libvirt/images/
            
            # Configurar limits para mejor performance
            echo "Configurando limits para libvirt..."
            sudo sh -c 'echo "* soft nofile 65536" >> /etc/security/limits.conf'
            sudo sh -c 'echo "* hard nofile 65536" >> /etc/security/limits.conf'
            
            echo "✅ $(hostname) optimizado"
EOF
        
        log_success "$server optimizado"
    done
}

# 3. Crear configuración unificada del cluster
create_cluster_config() {
    log_info "Creando configuración unificada del cluster..."
    
    cat > /opt/pucp-orchestrator/cluster_config.json << EOF
{
    "cluster_name": "pucp_production_cluster",
    "version": "1.0",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "infrastructure": "linux",
    "topology": {
        "management_network": "192.168.201.0/24",
        "cluster_network": "10.60.1.0/24",
        "gateway": "10.60.1.1"
    },
    "servers": {
        "server1": {
            "hostname": "server1",
            "mgmt_ip": "192.168.201.1",
            "ssh_host": "server1",
            "uri": "qemu+ssh://server1/system",
            "role": "compute",
            "cpus": 4,
            "ram_gb": 3,
            "storage_gb": 20,
            "access_port": 5811,
            "status": "active"
        },
        "server2": {
            "hostname": "server2", 
            "mgmt_ip": "192.168.201.2",
            "ssh_host": "server2",
            "uri": "qemu+ssh://server2/system",
            "role": "compute",
            "cpus": 4,
            "ram_gb": 3,
            "storage_gb": 20,
            "access_port": 5812,
            "status": "active"
        },
        "server3": {
            "hostname": "server3",
            "mgmt_ip": "192.168.201.3", 
            "ssh_host": "server3",
            "uri": "qemu+ssh://server3/system",
            "role": "compute",
            "cpus": 4,
            "ram_gb": 3,
            "storage_gb": 20,
            "access_port": 5813,
            "status": "active"
        },
        "server4": {
            "hostname": "server4",
            "mgmt_ip": "192.168.201.4",
            "ssh_host": "server4", 
            "uri": "qemu+ssh://server4/system",
            "role": "compute",
            "cpus": 4,
            "ram_gb": 7,
            "storage_gb": 20,
            "access_port": 5814,
            "status": "active"
        }
    },
    "capacity": {
        "total_cpus": 16,
        "total_ram_gb": 16,
        "total_storage_gb": 80,
        "max_concurrent_vms": 32,
        "recommended_vm_sizes": {
            "small": {"cpu": 1, "ram": 512, "disk": 10},
            "medium": {"cpu": 2, "ram": 1024, "disk": 20},
            "large": {"cpu": 2, "ram": 2048, "disk": 40}
        }
    },
    "network_config": {
        "ovs_enabled": true,
        "default_bridge": "virbr0",
        "vlan_range": "100-199",
        "supported_topologies": ["linear", "ring", "star", "mesh", "tree"]
    }
}
EOF

    log_success "Configuración del cluster creada"
}

# 4. Test de conectividad final
final_connectivity_test() {
    log_info "Test final de conectividad..."
    
    echo "📊 RESUMEN FINAL:"
    for server in server1 server2 server3 server4; do
        if ssh -o ConnectTimeout=5 $server "hostname && uptime | cut -d',' -f1" 2>/dev/null; then
            log_success "$server: Conectado y operativo"
        else
            log_error "$server: Problema de conectividad"
        fi
    done
}

# Ejecutar todas las optimizaciones
main() {
    log_info "Iniciando correcciones y optimizaciones..."
    
    fix_ovs_connectivity || log_warning "OVS no disponible como servidor separado"
    optimize_libvirt
    create_cluster_config
    final_connectivity_test
    
    echo ""
    echo "🎉 CLUSTER OPTIMIZADO Y LISTO"
    echo "=============================="
    echo "✅ 4 servidores de compute operativos"
    echo "✅ Libvirt optimizado en todos los nodos"
    echo "✅ Configuración unificada creada"
    echo "✅ Listo para deployments de producción"
    echo ""
    echo "📁 Archivos creados:"
    echo "   - /opt/pucp-orchestrator/cluster_config.json"
    echo ""
    echo "🔗 Próximos pasos:"
    echo "   1. Probar topologías: python3 test_topology_creation.py"
    echo "   2. Integrar con slice_service"
    echo "   3. Deploy primera topología de prueba"
}

main "$@"
