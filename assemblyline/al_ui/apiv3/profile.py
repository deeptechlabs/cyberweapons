
from flask import request
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE
from riak import RiakError

SUB_API = 'profile'
profile_api = core.make_subapi_blueprint(SUB_API)
profile_api._doc = "Manage the processing node's profiles"


# noinspection PyUnusedLocal
@profile_api.route("/<profilename>/", methods=["PUT"])
@api_login(require_admin=True)
def add_profile(profilename, **kwargs):
    """
    Add the profile information to the system
    
    Variables: 
    profilename       => Name of the profile
    
    Arguments:
    None
    
    Data Block:
    {"system_overrides": {            # Global variables 
         "AL_ROOT": "/al/",
         ...},
     "services": {                    # Enabled services
         "Mcafee": {                      # Name
             "workers": 3,                # Number of workers
             "service_overrides": {}},    # Service overrides
          ...}
    }
    
    Result example:
    { "success" : True }
    """
    data = request.json
    
    if not STORAGE.get_profile(profilename):
        STORAGE.save_profile(profilename, data)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, "You cannot add a profile that already exists...", 400)


# noinspection PyUnusedLocal
@profile_api.route("/<profilename>/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_profile(profilename, **kwargs):
    """
    Load the profile information
    
    Variables: 
    profilename       => Name of the profile
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"system_overrides": {            # Global variables 
         "AL_ROOT": "/al/",
         ...},
     "services": {                    # Enabled services
         "Mcafee": {                      # Name
             "workers": 3,                # Number of workers
             "service_overrides": {}},    # Service overrides
          ...}
    }
    """
    profile = STORAGE.get_profile(profilename)
    return make_api_response(profile)


# noinspection PyUnusedLocal
@profile_api.route("/list/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def list_profiles(**kwargs):
    """
    List all profiles available in the system
    
    Variables:
    offset       => Offset at which we start giving profiles
    length       => Numbers of profiles to return
    filter       => Filter to apply on the profiless list
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"count": 5,            # Number of profiles found
     "items": ["Profile 1", # List of profile names
               "Profile 2",
               ...]}
    """
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")

    try:
        return make_api_response(STORAGE.list_profiles(start=offset, rows=length, query=query))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


# noinspection PyUnusedLocal
@profile_api.route("/<profilename>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_profile(profilename, **kwargs):
    """
    Remove the profile information
    
    Variables: 
    profilename       => Name of the profile
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": True}    # Was is a success 
    """
    STORAGE.delete_profile(profilename)
    return make_api_response({"success": True})


# noinspection PyUnusedLocal
@profile_api.route("/<profilename>/", methods=["POST"])
@api_login(require_admin=True)
def set_profile(profilename, **kwargs):
    """
    Save the profile information to the system
    
    Variables: 
    profilename       => Name of the profile
    
    Arguments:
    None
    
    Data Block:
    {"system_overrides": {            # Global variables 
         "AL_ROOT": "/al/",
         ...},
     "services": {                    # Enabled services
         "Mcafee": {                      # Name
             "workers": 3,                # Number of workers
             "service_overrides": {}},    # Service overrides
          ...}
    }
    
    Result example:
    { "success" : True }
    """
    data = request.json
    
    STORAGE.save_profile(profilename, data)
    return make_api_response({"success": True})
