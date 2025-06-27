def select_driver(self, infrastructure: str):
    if infrastructure == 'linux':
        from .drivers.linux_driver import LinuxClusterDriver
        return LinuxClusterDriver()
    elif infrastructure == 'openstack':
        from .drivers.openstack_driver import OpenStackDriver
        return OpenStackDriver()
    else:
        raise ValueError(f"Unsupported infrastructure type: {infrastructure}")