from assemblyline.common.concurrency import execute_concurrently
from assemblyline.al.service.list_queue_sizes import get_service_queue_length
from al_ui.api_base import api_login, make_api_response
from al_ui.apiv3 import core
from al_ui.config import config, STORAGE

SUB_API = 'dashboard'
dashboard_api = core.make_subapi_blueprint(SUB_API)
dashboard_api._doc = "Display systems health"

EXPIRY_BUCKET_LIST = ["submission", "file", "alert", "result", "error", "filescore"]

###########################################################################
# Dashboard APIs


@dashboard_api.route("/expiry/", methods=["GET"])
@api_login(audit=False)
def get_expiry_(**_):
    """
    Check each buckets to make sure they don't have expired data that remains.
    Returns 'true' for each bucket that is fully expired.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
      "submission": true,
      "file": false,
      ...
    }
    """
    def run_query(bucket):
        return STORAGE.direct_search(bucket, "__expiry_ts__:[NOW/DAY TO NOW/DAY-2DAY]",
                                     args=[("rows", "0"), ("timeAllowed", "500")])['response']['numFound'] == 0

    return make_api_response(execute_concurrently([(run_query, (b, ), b) for b in EXPIRY_BUCKET_LIST]))


@dashboard_api.route("/overview/", methods=["GET"])
@api_login(audit=False)
def get_system_configuration_overview(**_):
    """
    Display a system configuration overview.
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {
     "errors": {          # Errors in the current config 
       "profiles": [],      # Profiles in error
       "services": [] },    # Services in error
     "services": {        # Services overview
       "SRV_NAME": {        # Single service overview 
         "enabled": True,     # is enabled?
         "profiles" : [],     # profiles referencing it
         "queue": 0,          # items in queue
         "workers": 1 },      # number of workers
       ...,} 
    }
    """
    errors = {"services": [], "profiles": []}
    services = {s["name"]: {"workers": 0, "enabled": s["enabled"], "profiles": [], "queue": 0}
                for s in STORAGE.list_services()}
    profiles = STORAGE.get_profiles_dict(list(set([p["_yz_rk"]
                                                   for p in STORAGE.stream_search("profile", "_yz_rk:*",
                                                                                  fl="_yz_rk")])))
    used_profiles = {n['mac_address']: n['profile'] for n in STORAGE.get_nodes(STORAGE.list_node_keys())
                     if n['profile'] != ""}
    
    for mac, used_p in used_profiles.iteritems():
        if profiles.has_key(used_p):
            for srv, cfg in profiles[used_p]["services"].iteritems():
                if not services.has_key(srv):
                    errors["services"].append({"service": srv, "profile": used_p})
                    continue
                services[srv]["workers"] += cfg["workers"]
                if used_p not in services[srv]["profiles"]:
                    services[srv]["profiles"].append(used_p)

            for srv, cfg in profiles[used_p]["virtual_machines"].iteritems():
                if not services.has_key(srv):
                    errors["services"].append({"service": srv, "profile": used_p})
                    continue

                vm = STORAGE.get_virtualmachine(srv)
                if not vm:
                    errors["services"].append({"service": srv, "profile": used_p})
                    continue

                services[srv]["workers"] += vm['num_workers'] * cfg['num_instances']
                if used_p not in services[srv]["profiles"]:
                    services[srv]["profiles"].append(used_p)
        else:
            errors["profiles"].append({"profile": used_p, "mac": mac})
    
    for srv in services:
        services[srv]["queue"] = get_service_queue_length(srv)

    return make_api_response({"services": services, "errors": errors})


@dashboard_api.route("/queues/", methods=["GET"])
@api_login(audit=False)
def list_queue_sizes(**_):
    """
    List services queue size for each services in the system.
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"MY SERVICE": 1, ... } # Dictionnary of services and number item in queue
    """
    services = list(set([s.get("classpath", None) for s in STORAGE.list_services()]))
    queue_lengths = {}
    for svc in services:
        queue_lengths[svc.split(".")[-1]] = get_service_queue_length(svc)

    return make_api_response(queue_lengths)


@dashboard_api.route("/services/", methods=["GET"])
@api_login(audit=False)
def list_services_workers(**_):
    """
    List number of workers for each services in the system.
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"MY SERVICE": 1, ... } # Dictionary of services and number of workers
    """
    services = {s["name"]: 0 for s in STORAGE.list_services() if s['enabled']}
    profiles = STORAGE.get_profiles_dict(list(set([p["_yz_rk"]
                                                   for p in STORAGE.stream_search("profile", "_yz_rk:*",
                                                                                  fl="_yz_rk")])))
    used_profiles = {n['mac_address']: n['profile'] for n in STORAGE.get_nodes(STORAGE.list_node_keys())
                     if n['profile'] != ""}

    for _mac, used_p in used_profiles.iteritems():
        if used_p in profiles:
            for srv, cfg in profiles[used_p]["services"].iteritems():
                if srv in services:
                    services[srv] += cfg["workers"]

            for srv, cfg in profiles[used_p]["virtual_machines"].iteritems():
                if srv in services:
                    vm = STORAGE.get_virtualmachine(srv)
                    if not vm:
                        continue
                    services[srv] += vm['num_workers'] * cfg['num_instances']

    return make_api_response(services, err=[profiles, used_profiles, services])


@dashboard_api.route("/shards/", methods=["GET"])
@api_login(audit=False)
def get_expected_shard_count(**_):
    """
    Get the number of dispatcher shards that are 
    supposed to be running in the system
    
    Variables:
    None
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    1         # Number of shards
    """
    return make_api_response({
        'dispatcher': config.core.dispatcher.shards,
        'middleman': config.core.middleman.shards,
    })
