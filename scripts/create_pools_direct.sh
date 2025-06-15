#!/bin/bash
SERVERS=("pucp-server1" "pucp-server2" "pucp-server3" "pucp-server4")

for server in "${SERVERS[@]}"; do
    echo "Configurando $server..."
    ssh "$server" "echo 'ubuntu' | sudo -S mkdir -p /var/lib/libvirt/images"
    ssh "$server" "echo 'ubuntu' | sudo -S chown root:libvirt /var/lib/libvirt/images"
    ssh "$server" "echo 'ubuntu' | sudo -S chmod 775 /var/lib/libvirt/images"
    ssh "$server" "virsh pool-define-as default dir - - - - '/var/lib/libvirt/images'"
    ssh "$server" "virsh pool-build default"
    ssh "$server" "virsh pool-start default"
    ssh "$server" "virsh pool-autostart default"
    echo "✅ $server listo"
done
