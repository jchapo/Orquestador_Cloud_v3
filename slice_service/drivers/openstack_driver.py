from .openstack_driver_simple import SimpleOpenStackDriver

class OpenStackDriver:
    def __init__(self):
        self.driver = SimpleOpenStackDriver()
    
    def create_vm(self, vm_config, placement=None):
        if placement:
            vm_config['placement'] = placement
        return self.driver.create_vm_simple(vm_config)
    
    def get_available_resources(self):
        # Implementación básica
        return {
            'worker1': {'vcpu': 2, 'ram': 2048, 'disk': 20},
            'worker2': {'vcpu': 2, 'ram': 2048, 'disk': 20},
            'worker3': {'vcpu': 2, 'ram': 2048, 'disk': 20}
        }
