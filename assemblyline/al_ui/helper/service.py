
from al_ui.config import STORAGE, SYSTEM_SERVICE_CATEGORY_NAME


def get_default_service_spec(srv_list=None):
    if not srv_list:
        srv_list = STORAGE.list_services()
        
    return [{"name": x['name'],
             "params": x["submission_params"]}
            for x in srv_list if x["submission_params"]]


def get_default_service_list(srv_list=None, default_selection=None):
    if not default_selection:
        default_selection = ["Extraction", "Static Analysis", "Filtering", "Antivirus", "Post-Processing"]
    if not srv_list:
        srv_list = STORAGE.list_services()
    
    services = {}
    for item in srv_list:
        grp = item['category']

        if grp == SYSTEM_SERVICE_CATEGORY_NAME:
            continue
        if not services.has_key(grp):
            services[grp] = []

        services[grp].append({"name": item["name"],
                              "category": grp,
                              "selected": (grp in default_selection or item['name'] in default_selection),
                              "is_external": item["is_external"]})
    
    return [{"name": k, "selected": k in default_selection, "services": v} for k, v in services.iteritems()]


def simplify_services(services):
    out = []
    for item in services:
        if item["selected"]:
            out.append(item["name"])
        else:
            for srv in item["services"]:
                if srv["selected"]:
                    out.append(srv["name"])
                    
    return out


def simplify_service_spec(service_spec):
    params = {}
    for spec in service_spec:
        service = spec['name']
        for param in spec['params']:
            if param['value'] != param['default']:
                params[service] = params.get(service, {})
                params[service][param['name']] = param['value']
    
    return params


def ui_to_dispatch_task(task, uname, sid=None):
    # Simplify services params
    if "service_spec" in task:
        task["params"] = simplify_service_spec(task["service_spec"])
        del(task['service_spec'])
        
    # Simplify service selection
    if "services" in task:
        task['selected'] = simplify_services(task["services"])
        del(task['services'])
    
    # Add username
    task['submitter'] = uname
    
    if sid:
        task['sid'] = sid
    
    # Remove UI specific params
    if "download_encoding" in task:
        del(task['download_encoding'])
    if "expand_min_score" in task:
        del(task['expand_min_score'])
    if "hide_raw_results" in task:
        del(task['hide_raw_results'])
    
    return task
