#!/usr/bin/env python3
"""
Script para actualizar la función _generate_vm_xml en linux_driver.py
"""

import re

def update_generate_vm_xml():
    file_path = "/opt/pucp-orchestrator/slice_service/drivers/linux_driver.py"
    
    # Leer el archivo actual
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Nueva función _generate_vm_xml corregida
    new_function = '''    def _generate_vm_xml(self, vm_config: Dict, disk_path: str, 
                        server_name: str, slice_id: str = None, 
                        networks: List[Dict] = None) -> str:
        """Genera XML de configuración de la VM"""
        
        vm_name = vm_config['name']
        vm_uuid = str(uuid.uuid4())
        ram_mb = vm_config['ram']
        vcpus = vm_config['cpu']
        
        # Generar MAC address única
        mac_address = self._generate_mac_address(vm_name, server_name)
        
        xml_template = f"""<domain type='kvm'>
  <name>{vm_name}</name>
  <uuid>{vm_uuid}</uuid>
  <metadata>
    <pucp:slice_id xmlns:pucp='http://pucp.edu.pe/orchestrator'>{slice_id or 'unknown'}</pucp:slice_id>
    <pucp:server xmlns:pucp='http://pucp.edu.pe/orchestrator'>{server_name}</pucp:server>
  </metadata>
  <memory unit='MiB'>{ram_mb}</memory>
  <currentMemory unit='MiB'>{ram_mb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-5.2'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
    </disk>
    <controller type='usb' index='0' model='qemu-xhci' ports='15'>
      <address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
    </controller>
    <controller type='sata' index='0'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x1f' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='1' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='1' port='0x10'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0' multifunction='on'/>
    </controller>
    <controller type='pci' index='2' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='2' port='0x11'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x1'/>
    </controller>
    <controller type='pci' index='3' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='3' port='0x12'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x2'/>
    </controller>
    <controller type='pci' index='4' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='4' port='0x13'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x3'/>
    </controller>
    <controller type='virtio-serial' index='0'>
      <address type='pci' domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
    </controller>
    <interface type='network'>
      <mac address='{mac_address}'/>
      <source network='ovs-network'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
      <address type='virtio-serial' controller='0' bus='0' port='1'/>
    </channel>
    <input type='tablet' bus='usb'>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <sound model='ich9'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x1b' function='0x0'/>
    </sound>
    <video>
      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <address type='pci' domain='0x0000' bus='0x05' slot='0x00' function='0x0'/>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
      <address type='pci' domain='0x0000' bus='0x06' slot='0x00' function='0x0'/>
    </rng>
  </devices>
</domain>"""
        
        return xml_template'''
    
    # Patrón para encontrar la función actual
    pattern = r'(    def _generate_vm_xml.*?)(\n    def [^_]|\n\n    def [^_]|\nclass |\Z)'
    
    # Buscar y reemplazar
    match = re.search(pattern, content, re.DOTALL)
    if match:
        # Reemplazar la función
        updated_content = content[:match.start(1)] + new_function + content[match.start(2):]
        
        # Escribir el archivo actualizado
        with open(file_path, 'w') as f:
            f.write(updated_content)
        
        print("✅ Función _generate_vm_xml actualizada exitosamente")
        print("🔧 Cambio principal: <interface type='bridge'> → <interface type='network'>")
        return True
    else:
        print("❌ No se pudo encontrar la función _generate_vm_xml")
        return False

if __name__ == "__main__":
    update_generate_vm_xml()
