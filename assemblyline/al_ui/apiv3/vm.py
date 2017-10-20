
from flask import request
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE
from al_ui.http_exceptions import AccessDeniedException

SUB_API = 'vm'
vm_api = core.make_subapi_blueprint(SUB_API)
vm_api._doc = "Manage the different Virtual machines of the system"


@vm_api.route("/<vm>/", methods=["PUT"])
@api_login(require_admin=True)
def add_virtual_machine(vm, **_):
    """
    Add the vm configuration to the system
    
    Variables: 
    vm       => Name of the vm
    
    Arguments:
    None
    
    Data Block:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of service workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds interval
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }
    
    Result example:
    { "success" : True }
    """
    data = request.json
    
    if not STORAGE.get_virtualmachine(vm):
        STORAGE.save_virtualmachine(vm, data)

        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, "You cannot add a vm that already exists...", 400)


@vm_api.route("/<vm>/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_virtual_machine(vm, **_):
    """
    Load the configuration for a given virtual machine
    
    Variables: 
    vm       => Name of the virtual machine to get the info
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds interval
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }                
    """
    return make_api_response(STORAGE.get_virtualmachine(vm))


@vm_api.route("/list/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def list_virtual_machine(**_):
    """
    List all virtual machines of the system.
    
    Variables:
    offset       => Offset at which we start giving virtual machines
    length       => Numbers of virtual machines to return
    filter       => Filter to apply on the virtual machines list
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    [   {
         enabled: true,                  # Is VM enabled
         name: "Extract",                # Name of the VM
         num-workers: 1,                 # Number of service workers in that VM
         os_type: "windows",             # Type of OS
         os_variant: "win7",             # Variant of OS
         ram: 1024,                      # Amount of RAM
         revert_every: 600,              # Auto revert seconds interval
         vcpus: 1,                       # Number of CPUs
         virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
        },
    ...]
    """
    return make_api_response(STORAGE.list_virtualmachines())


@vm_api.route("/<vm>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_virtual_machine(vm, **_):
    """
    Remove the vm configuration
    
    Variables: 
    vm       => Name of the vm
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": True}    # Was is a success 
    """
    STORAGE.delete_virtualmachine(vm)
    STORAGE.delete_profile(vm)
    return make_api_response({"success": True})


@vm_api.route("/<vm>/", methods=["POST"])
@api_login(require_admin=True)
def set_virtual_machine(vm, **_):
    """
    Save the configuration of a given virtual machine
    
    Variables: 
    vm    => Name of the virtual machine
    
    Arguments: 
    None
    
    Data Block:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds intervale
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }
    
    Result example:
    {"success": true }    #Saving the virtual machine info succeded
    """
    data = request.json
    
    try:
        if vm != data['name']:
            raise AccessDeniedException("You are not allowed to change the virtual machine name.")
        
        return make_api_response({"success": STORAGE.save_virtualmachine(vm, data)})
    except AccessDeniedException, e:
        return make_api_response({"success": False}, e.message, 403)
