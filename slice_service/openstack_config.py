OPENSTACK_CONFIG = {
    'auth_url': 'http://10.60.2.21:5000/v3',
    'username': 'admin',
    'password': 'openstack123',
    'project_name': 'admin',
    'user_domain_name': 'Default',
    'project_domain_name': 'Default',
    'region_name': 'RegionOne',
    
    'provider_network': 'provider',
    'external_network': 'external',
    'physical_network': 'physnet1',
    'vlan_range': '200:299',
    
    'compute_nodes': {
        'pucp-worker1': {
            'availability_zone': 'nova',
            'hypervisor_hostname': 'pucp-worker1'
        },
        'pucp-worker2': {
            'availability_zone': 'nova',
            'hypervisor_hostname': 'pucp-worker2'
        },
        'pucp-worker3': {
            'availability_zone': 'nova',
            'hypervisor_hostname': 'pucp-worker3'
        }
    },
    
    'default_quotas': {
        'instances': 50,
        'cores': 100,
        'ram': 102400,  # MB
        'floating_ips': 20,
        'security_groups': 50,
        'security_group_rules': 200
    }
}