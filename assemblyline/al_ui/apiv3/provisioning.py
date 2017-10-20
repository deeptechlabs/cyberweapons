import copy
import json

from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response
from flask import request
from assemblyline.al.common.provisioning import Machine, ProvisioningException
from assemblyline.al.common.provisioning import ServiceAllocation
from assemblyline.al.common.provisioning import ServicePodAllocation
from assemblyline.al.common.provisioning import VmAllocation
from assemblyline.al.common import provisioning

SUB_API = 'provisioning'
provisioning_api = core.make_subapi_blueprint(SUB_API)
provisioning_api._doc = "Manage the different processing nodes"


# noinspection PyTypeChecker,PyUnusedLocal
@provisioning_api.route("/plan/apply/", methods=["POST"])
@api_login(require_admin=True)
def apply_plan(**kwargs):
    """
    Applies a provisioning plan to the cluster

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
        profiles: {},   # A dictionary of profiles where name of profile is the key
        flex_nodes: []  # A list machine mac addresses that will be used for flex
    }

    Result example:
    {"success": true}
    """
    data = request.json
    if not data:
        return make_api_response({}, "There are not profiles to apply", 400)

    profiles = data.get('profiles', {})
    flex_nodes = data.get("flex_nodes", [])

    # Save flex nodes
    for idx, mac in enumerate(flex_nodes):
        profile_id = "flex.%s" % idx
        STORAGE.save_profile(profile_id, {'services': {}, 'system_overrides': {}, 'virtual_machines': {}})
        node = STORAGE.get_node(mac)
        node['profile'] = profile_id
        STORAGE.save_node(mac, node)

    # Save profiles
    for profile_name, profile_data in profiles.iteritems():
        mac = profile_name.rsplit("-", 1)[1]
        STORAGE.save_profile(profile_name, profile_data)
        node = STORAGE.get_node(mac)
        node['profile'] = profile_name
        STORAGE.save_node(mac, node)

    return make_api_response({"success": True})


# noinspection PyUnusedLocal
@provisioning_api.route("/config/<name>/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_cluster_config(name, **kwargs):
    data = STORAGE.get_blob("prov_conf_%s" % name)
    if not data:
        return make_api_response({}, "Provisionning config %s not found." % name, 404)
    return make_api_response(data)


# noinspection PyUnusedLocal
@provisioning_api.route("/config/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def load_running_config(**kwargs):
    """
    Loads the currently running cluster configuration

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "allocation": {         # Resource allocation table
            "MyService": 3,     # Service / VM and the number to allocate
             ...
        },
        "flex": 3               # Number of flex nodes to reserve
    }
    """
    profile_map = STORAGE.get_all_profiles()
    hosts = STORAGE.list_node_keys()
    host_list = sorted([host for host in STORAGE.get_nodes(hosts)
                        if host is not None and 'hostagent' in host.get('roles', [])],
                       key=lambda k: (k.get('machine_info', {}).get('cores', 1),
                                      k.get('machine_info', {}).get('name', 1)))

    flex_count = 0
    allocation = {}
    overrides = {}
    for host in host_list:
        profile_name = host.get('profile', None)
        if profile_name.startswith('flex'):
            flex_count += 1
        else:
            host_profile = profile_map.get(profile_name, {})
            if host_profile:
                for service in host_profile['services']:
                    alloc_key = 'svc_%s' % service
                    if alloc_key not in allocation:
                        allocation[alloc_key] = 0
                    allocation[alloc_key] += host_profile['services'][service]['workers']
                    if host_profile['services'][service]["service_overrides"]:
                        if service not in overrides:
                            overrides[service] = []
                        override_dict = host_profile['services'][service]["service_overrides"]
                        overrides[service].append({'count': host_profile['services'][service]['workers'],
                                                  'override': json.dumps(override_dict)})
                for vm in host_profile['virtual_machines']:
                    alloc_key = 'vm_%s' % vm
                    if alloc_key not in allocation:
                        allocation[alloc_key] = 0
                    allocation[alloc_key] += host_profile['virtual_machines'][vm]['num_instances']
                pass

    return make_api_response({'allocation': allocation, 'flex': flex_count, 'overrides': overrides})


# noinspection PyUnusedLocal
@provisioning_api.route("/info/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def load_system_info(**kwargs):
    """
    Load the full system information

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "vms": {},      # Map of vms that are available in the system
        "services": {}, # Map of service that are available in the system
        "hosts": []     # List of physical hosts configured
    }
    """
    temp_service_map = {x['name']: x for x in STORAGE.list_services()}
    vm_list = STORAGE.list_virtualmachines()
    hosts = STORAGE.list_node_keys()
    host_list = sorted([host for host in STORAGE.get_nodes(hosts)
                        if host is not None and 'hostagent' in host.get('roles', [])],
                       key=lambda k: (k.get('machine_info', {}).get('cores', 1),
                                      k.get('machine_info', {}).get('memory', '11.7'),
                                      k.get('machine_info', {}).get('name', 1)))

    service_map = copy.copy(temp_service_map)
    out_vm_map = {}
    for vm in vm_list:
        service_name = vm['name']
        srv_list = {
            service_name: vm['num_workers']
        }
        cpu_usage = temp_service_map.get(service_name, {}).get('cpu_cores', 1) * vm['num_workers']

        out_vm_map[service_name] = {"cpu_usage": cpu_usage,
                                    "ram_usage": vm['ram'],
                                    "services": srv_list,
                                    "enabled": vm.get("enabled", False)}

        try:
            del service_map[service_name]
        except KeyError:
            continue

    out_service_map = {}
    for service in service_map.itervalues():
        out_service_map[service['name']] = {"cpu_usage": service.get('cpu_cores', 1),
                                            "ram_usage": service.get('ram_mb', 1024),
                                            "enabled": service.get("enabled", False)}

    out_host_list = []
    for host in host_list:
        out_host_list.append({"hostname": host['machine_info']['name'],
                              "profile": host['profile'],
                              "cores": host['machine_info']['cores'],
                              "memory": float(host['machine_info']['memory']) * 1024,
                              "mac": host['mac_address']})

    return make_api_response({'vms': out_vm_map,
                              'services': out_service_map,
                              "hosts": out_host_list})


# noinspection PyUnusedLocal
@provisioning_api.route("/config/<name>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_cluster_config(name, **kwargs):
    STORAGE.delete_blob("prov_conf_%s" % name)
    return make_api_response({"success": True})


# noinspection PyUnusedLocal
@provisioning_api.route("/config/<name>/", methods=["POST"])
@api_login(require_admin=True)
def set_cluster_config(name, **kwargs):
    data = request.json
    if not data:
        return make_api_response({}, "There are no provisionning config to save", 400)

    if 'allocation' not in data or 'flex' not in data or 'overrides' not in data:
        return make_api_response({}, "Invalid provisioning config", 400)

    STORAGE.save_blob("prov_conf_%s" % name, data)
    return make_api_response({"success": True})


# noinspection PyTypeChecker,PyUnusedLocal
@provisioning_api.route("/plan/test/", methods=["POST"])
@api_login(require_admin=True)
def test_cluster_plan(**kwargs):
    """
    Test a cluster plan into the provisioner

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
        'services': {},         # Map of possible services to allocate
        'vms': {},              # Map of possible VMs to allocate
        'allocation': {},       # Allocation data
        'flex': 0,              # Number of flex nodes to create
        'hosts': [],            # List of available host in the cluster
        'overrides': {},          # Map of special service allocation
    }

    Result example:
    {
        "allocation_data": {},  # Cluster allocation data
        "flex_nodes": []        # List of mac for hosts that will be flex
    }
    """
    def _provision(machines, allocs, overrides):
        machine_list = [Machine("%s-%s" % (x['hostname'], x['mac']), x['cores'], x['memory']) for x in machines]
        provisioner = provisioning.ClusterProvisioner(machine_list, allocs, overrides)
        return provisioner.run(print_summary=False)

    data = request.json
    if not data:
        return make_api_response({}, "There are not plan to test", 400)

    overrides_allocation = []
    for svc in data['overrides']:
        svc_override = data['overrides'][svc]
        service_alloc = ServiceAllocation(svc,
                                          data['services'][svc]['cpu_usage'],
                                          data['services'][svc]['ram_usage'],
                                          svc)
        for override in svc_override:
            overrides_allocation.append(ServicePodAllocation(service_alloc, override['count'],
                                                             json.loads(override['override'])))
            data['allocation']['svc_' + svc] -= override['count']

    allocation = [(ServiceAllocation(s, data['services'][s]['cpu_usage'], data['services'][s]['ram_usage'], s),
                   data['allocation']['svc_' + s])
                  for s in data['services'].keys()
                  if data['allocation']['svc_' + s] > 0]

    allocation.extend([(VmAllocation(v,
                                     data['vms'][v]['cpu_usage'],
                                     data['vms'][v]['ram_usage'],
                                     data['vms'][v]['services'].keys()),
                        data['allocation']['vm_' + v])
                       for v in data['vms'].keys()
                       if data['allocation']['vm_' + v] != 0])

    flex_nodes = [m['mac'] for m in data['hosts'][:data['flex']]]
    other_nodes = data['hosts'][data['flex']:]

    cluster_allocation_data = {}
    try:
        # Reverse sorting strategy
        other_nodes = other_nodes[::-1]
        cluster_allocation_data = _provision(other_nodes, allocation, overrides_allocation)
    except ProvisioningException:
        try:
            # Ascending cores startegy
            other_nodes = sorted(other_nodes, key=lambda k: k.get('cores', 1))
            cluster_allocation_data = _provision(other_nodes, allocation, overrides_allocation)
        except ProvisioningException:
            try:
                # Ascending memory strategy
                other_nodes = sorted(other_nodes, key=lambda k: k.get('memory', 1024))
                cluster_allocation_data = _provision(other_nodes, allocation, overrides_allocation)
            except ProvisioningException:
                try:
                    # Ascending hostname strategy
                    other_nodes = sorted(other_nodes, key=lambda k: (k['hostname'], k['mac']))
                    cluster_allocation_data = _provision(other_nodes, allocation, overrides_allocation)
                except ProvisioningException:

                    return make_api_response({}, "Provisionner failed to allocate the current plan. "
                                                 "Reduce the number of VMs and/or services.", status_code=500)

    return make_api_response({"allocation_data": cluster_allocation_data, "flex_nodes": flex_nodes})
