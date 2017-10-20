from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response
from flask import request
from al_ui.http_exceptions import AccessDeniedException

SUB_API = 'host'
host_api = core.make_subapi_blueprint(SUB_API)
host_api._doc = "Manage the different processing nodes"

@host_api.route("/<mac>/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_host(mac, *args, **kwargs):
    """
    Load the host information
    
    Variables: 
    mac       => MAC Address of the host to get the info
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {
     "profile": "Default profile",  # Host current profile 
     "machine_info": {              # Host Machine info block
       "uid": "Core-001122334455",    # Machine UID
       "ip": "127.0.0.1",             # Machine IP
       "memory": "23.5",              # Machine RAM (GB)
       "cores": 16,                   # Machine Num Cores
       "os": "Linux",                 # Machine OS
       "name": "computer1" },         # Machine Name
     "ip": "127.0.0.1",             # Host IP
     "hostname": "computer1",       # Host Name
     "enabled": true,               # Is host enabled?
     "platform": {                  # Host platform block
       "node": "computer1",           # Node name
       "system": "Linux",             # Node system
       "machine": "x86_64",           # Node Architecture
       "version": "#47-Ubuntu SMP",   # Node Kernel version
       "release": "3.13.0-24",        # Node Kernel release
       "proc": "x86_64" },            # Node proc Architecture
     "mac_address": "001122334455"  # Host Mac address
    }
    """
    return make_api_response(STORAGE.get_node(mac))

@host_api.route("/list/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def list_hosts(*args, **kwargs):
    """
    List all hosts registered in the system
    
    Variables:
    None
    
    Arguments:
    offset       =>  Offset in the host bucket
    length       =>  Max number of host returned
    
    Data Block:
    None
    
    Result example:
    {
     "total": 13,                   # Total Number of hosts
     "count": 100,                  # Number of hosts requested
     "offset": 0,                   # Offset in the host bucket
     "items": [{                    # List of host blocks
       "profile": "Default profile",  # Host current profile 
       "machine_info": {              # Host Machine info block
         "uid": "Core-001122334455",    # Machine UID
         "ip": "127.0.0.1",             # Machine IP
         "memory": "23.5",              # Machine RAM (GB)
         "cores": 16,                   # Machine Num Cores
         "os": "Linux",                 # Machine OS
         "name": "computer1" },         # Machine Name
       "ip": "127.0.0.1",             # Host IP
       "hostname": "computer1",       # Host Name
       "enabled": true,               # Is host enabled?
       "platform": {                  # Host platform block
         "node": "computer1",           # Node name
         "system": "Linux",             # Node system
         "machine": "x86_64",           # Node Architecture
         "version": "#47-Ubuntu SMP",   # Node Kernel version
         "release": "3.13.0-24",        # Node Kernel release
         "proc": "x86_64" },            # Node proc Architecture
       "mac_address": "001122334455"  # Host Mac address
       }, ... ]
    }
    """
    hosts = STORAGE.list_node_keys()
    host_list = sorted([host for host in STORAGE.get_nodes(hosts) if host is not None], key=lambda x: x['hostname'])
    return make_api_response({'items': host_list, 'count': len(host_list)})


@host_api.route("/<mac>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_host(mac, *args, **kwargs):
    """
    Delete a host from the system
    
    Variables: 
    mac       => MAC Address of the host to be deleted
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": True}
    """
    STORAGE.delete_node(mac)
    return make_api_response({"success": True})


@host_api.route("/<mac>/", methods=["POST"])
@api_login(require_admin=True)
def set_host(mac, *args, **kwargs):
    """
    Set the host information
    
    Variables: 
    mac       => MAC Address of the host to get the info
    
    Arguments:
    None
    
    Data Block:
    {
     "profile": "Default profile",  # Host current profile 
     "machine_info": {              # Host Machine info block
       "uid": "Core-001122334455",    # Machine UID
       "ip": "127.0.0.1",             # Machine IP
       "memory": "23.5",              # Machine RAM (GB)
       "cores": 16,                   # Machine Num Cores
       "os": "Linux",                 # Machine OS
       "name": "computer1" },         # Machine Name
     "ip": "127.0.0.1",             # Host IP
     "hostname": "computer1",       # Host Name
     "enabled": true,               # Is host enabled?
     "platform": {                  # Host platform block
       "node": "computer1",           # Node name
       "system": "Linux",             # Node system
       "machine": "x86_64",           # Node Architecture
       "version": "#47-Ubuntu SMP",   # Node Kernel version
       "release": "3.13.0-24",        # Node Kernel release
       "proc": "x86_64" },            # Node proc Architecture
     "mac_address": "001122334455"  # Host Mac address
    }
    
    Result example:
    {
     "status": "success"            # Was saving successful ?
    }
    """
    
    data = request.json
    
    if mac != data['mac_address']:
        raise AccessDeniedException("You are not allowed to change the host MAC Address.")
    
    return make_api_response(STORAGE.save_node(mac, data))

