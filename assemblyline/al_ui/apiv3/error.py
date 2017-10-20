
from flask import request
from assemblyline.al.common import forge
from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response
from riak import RiakError
config = forge.get_config()

SUB_API = 'error'

Classification = forge.get_classification()

error_api = core.make_subapi_blueprint(SUB_API)
error_api._doc = "Perform operations on service errors"


@error_api.route("/<error_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_error(error_key, **kwargs):
    """
    Get the error details for a given error key
    
    Variables:
    error_key         => Error key to get the details for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
        KEY: VALUE,   # All fields of an error in key/value pair
    }
    """
    user = kwargs['user']
    data = STORAGE.get_error(error_key)
    
    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to see this error...", 403)


@error_api.route("/list/", methods=["GET"])
@api_login(require_admin=True)
def list_errors(**kwargs):
    """
    List all error in the system (per page)
    
    Variables:
    None
    
    Arguments: 
    offset       => Offset at which we start giving errors
    length       => Numbers of errors to return
    filter       => Filter to apply to the error list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total errors found
     "offset": 0,                 # Offset in the error list
     "count": 100,                # Number of errors returned
     "items": []                  # List of error blocks
    }
    """
    user = kwargs['user']
    
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")

    try:
        return make_api_response(STORAGE.list_errors(query, start=offset, rows=length,
                                                     access_control=user["access_control"]))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise
