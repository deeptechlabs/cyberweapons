
from flask import request
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE
from al_ui.helper.result import format_result
from al_ui.http_exceptions import AccessDeniedException
from assemblyline.al.common import forge
config = forge.get_config()

SUB_API = 'service'

service_api = core.make_subapi_blueprint(SUB_API)
service_api._doc = "Manage the different services"


@service_api.route("/<servicename>/", methods=["PUT"])
@api_login(require_admin=True)
def add_service(servicename, **_):
    """
    Add a service configuration
    
    Variables: 
    servicename    => Name of the service to add
    
    Arguments: 
    None
    
    Data Block:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extracts some stuff"
     'enabled': True,
     'install_by_default': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'supported_platforms': ['Linux'],
     'timeout': 60}
    
    Result example:
    {"success": true }    #Saving the user info succeded
    """
    data = request.json
    
    if not STORAGE.get_service(servicename):
        STORAGE.save_service(servicename, data)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, "You cannot add a service that already exists...", 400)


@service_api.route("/constants/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_service_constants(**_):
    """
    Get global service constants.
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
        "categories": [
          "Antivirus", 
          "Extraction", 
          "Static Analysis", 
          "Dynamic Analysis"
        ], 
        "stages": [
          "FILTER", 
          "EXTRACT", 
          "SECONDARY", 
          "TEARDOWN"
        ]
    }
    """
 
    constants = forge.get_constants()
    service_constants = {
        'stages': constants.SERVICE_STAGES,
        'categories': constants.SERVICE_CATEGORIES,
    }
    return make_api_response(service_constants)


@service_api.route("/multiple/keys/", methods=["POST"])
@api_login(audit=False, required_priv=['R'])
def get_multiple_service_keys(**kwargs):
    """
    Get multiple result and error keys at the same time
        
    Variables:
    None
                         
    Arguments: 
    None
    
    Data Block:
    {"error": [],      #List of error keys to lookup
     "result": []      #List of result keys to lookup
    }
    
    Result example:
    {"error": {},      #Dictionary of error object matching the keys
     "result": {}      #Dictionary of result object matching the keys
    }
    """
    user = kwargs['user']
    data = request.json
    
    errors = STORAGE.get_errors_dict(data['error'])
    results = STORAGE.get_results_dict(data['result'])

    srls = list(set([x[:64] for x in results.keys()]))
    file_infos = STORAGE.get_files_dict(srls)
    for r_key in results.keys():
        r_value = format_result(user['classification'], results[r_key], file_infos[r_key[:64]]['classification'])
        if not r_value:
            del results[r_key]
        else:
            results[r_key] = r_value
            
    out = {"error": errors, "result": results}
    
    return make_api_response(out)


@service_api.route("/<servicename>/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def get_service(servicename, **_):
    """
    Load the configuration for a given service
    
    Variables: 
    servicename       => Name of the service to get the info
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extracts some stuff"
     'enabled': True,
     'install_by_default': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'supported_platforms': ['Linux'],
     'timeout': 60}
    """
    return make_api_response(STORAGE.get_service(servicename))


@service_api.route("/error/<path:cache_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_service_error(cache_key, **_):
    """
    Get the content off a given service error cache key.
        
    Variables:
    cache_key     => Service result cache key
                     as (SRL.ServiceName)
                            
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"response": {                   # Service Response                      
         "milestones": {},              # Timing object
         "supplementary": [],           # Supplementary files  
         "status": "FAIL",              # Status
         "service_version": "",         # Service Version
         "service_name": "NSRL",        # Service Name
         "extracted": [],               # Extracted files
         "score": 0,                    # Service Score
         "message": "Err Message"},     # Error Message
     "result": []}                   # Result objets
    """
    data = STORAGE.get_error(cache_key)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)
     
    return make_api_response(data)


@service_api.route("/result/<path:cache_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_service_result(cache_key, **kwargs):
    """
    Get the result for a given service cache key.
        
    Variables:
    cache_key         => Service result cache key
                         as SRL.ServiceName.ServiceVersion.ConfigHash
                         
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"response": {                        # Service Response
       "milestones": {},                    # Timing object
       "supplementary": [],                 # Supplementary files  
       "service_name": "Mcafee",            # Service Name
       "message": "",                       # Service error message
       "extracted": [],                     # Extracted files
       "service_version": "v0"},            # Service Version
     "result": {                          # Result objects
       "score": 1302,                       # Total score for the file 
       "sections": [{                       # Result sections
         "body": "Text goes here",            # Body of the section (TEXT)
         "classification": "",                # Classification
         "links": [],                         # Links inside the section
         "title_text": "Title",               # Title of the section
         "depth": 0,                          # Depth (for Display purposes)
         "score": 500,                        # Section's score
         "body_format": null,                 # Body format
         "subsections": []                    # List of sub-sections
         }, ... ], 
       "classification": "",                # Maximum classification for service
       "tags": [{                           # Generated Tags
         "usage": "IDENTIFICATION",           # Tag usage 
         "value": "Tag Value",                # Tag value
         "type": "Tag Type",                  # Tag type
         "weight": 50,                        # Tag Weight
         "classification": ""                 # Tag Classification
         }, ...]
       }
    }
    """
    user = kwargs['user']
    data = STORAGE.get_result(cache_key)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    cur_file = STORAGE.get_file(cache_key[:64])
    data = format_result(user['classification'], data, cur_file['classification'])
    if not data:
        return make_api_response("", "You are not allowed to view the results for this key", 403)
    
    return make_api_response(data)


@service_api.route("/list/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def list_services(**__):
    """
    List all service configurations of the system.
    
    Variables:
    None

    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
     [
        {'accepts': ".*"
         'category': 'Extraction',
         'classpath': 'al_services.alsvc_extract.Extract',
         'description': "Extracts some stuff",
         'enabled': True,
         'name': 'Extract',
         'rejects': 'empty'
         'stage': 'CORE'
         },
         ...
     ]
    """
    resp = [{'accepts': x.get('accepts', None),
             'category': x.get('category', None),
             'classpath': x.get('classpath', None),
             'description': x.get('description', None),
             'enabled': x.get('enabled', False),
             'name': x.get('name', None),
             'rejects': x.get('rejects', None),
             'stage': x.get('stage', None)}
            for x in STORAGE.list_services()]

    return make_api_response(resp)


@service_api.route("/<servicename>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_service(servicename, **_):
    """
    Remove a service configuration
    
    Variables: 
    servicename       => Name of the service to remove
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": true}  # Has the deletion succeeded
    """
    STORAGE.delete_service(servicename)
    return make_api_response({"success": True})


@service_api.route("/<servicename>/", methods=["POST"])
@api_login(require_admin=True)
def set_service(servicename, **_):
    """
    Save the configuration of a given service
    
    Variables: 
    servicename    => Name of the service to save
    
    Arguments: 
    None
    
    Data Block:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extract some stuff",
     'enabled': True,
     'install_by_default': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'supported_platforms': ['Linux'],
     'timeout': 60}
    
    Result example:
    {"success": true }    #Saving the user info succeded
    """
    data = request.json
    
    try:
        if servicename != data['name']:
            raise AccessDeniedException("You are not allowed to change the service name.")
        
        return make_api_response({"success": STORAGE.save_service(servicename, data)})
    except AccessDeniedException, e:
        return make_api_response({"success": False}, e.message, 403)
