
from copy import deepcopy
from flask import request

from assemblyline.al.common.heuristics import list_all_heuristics
from al_ui.apiv3 import core
from assemblyline.al.common import forge
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response

SUB_API = 'heuristics'

Classification = forge.get_classification()

heuristics_api = core.make_subapi_blueprint(SUB_API)
heuristics_api._doc = "View the different heuristics of the system"

HEUR, HEUR_MAP = list_all_heuristics(STORAGE.list_services())


@heuristics_api.route("/<heuristic_id>/", methods=["GET"])
@api_login()
def get_heuristic(heuristic_id, **kwargs):
    """
    Get a specific heuristic's detail from the system
    
    Variables:
    heuristic_id  => ID of the heuristic
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"id": "AL_HEUR_001",               # Heuristics ID
     "filetype": ".*",                  # Target file type
     "name": "HEURISTICS_NAME",         # Heuristics name
     "description": ""}                 # Heuristics description
    """
    user = kwargs['user']

    h = deepcopy(HEUR_MAP.get(heuristic_id, None))

    if not h:
        return make_api_response("", "Not found", 404)

    # Add counters
    h["count"] = 0
    h["min"] = 0
    h["avg"] = 0
    h["max"] = 0

    heur_blob = STORAGE.get_blob("heuristics_stats")
    if heur_blob:
        data = heur_blob.get('stats', {}).get(heuristic_id, None)
        if data:
            h["count"] = data[0]
            h["min"] = data[1]
            h["avg"] = data[2]
            h["max"] = data[3]

    if user and Classification.is_accessible(user['classification'], h['classification']):
        return make_api_response(h)
    else:
        return make_api_response("", "You are not allowed to see this heuristic...", 403)


@heuristics_api.route("/list/", methods=["GET"])
@api_login()
def list_heuritics(**kwargs):
    """
    List all heuristics in the system
    
    Variables:
    offset     =>  Offset to start returning results
    length     =>  Number of results to return
    query      =>  Query to use to filter the results
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/heuristics/SW_HEUR_001/
    
    Result example:
    {"total": 201,                # Total heuristics found
     "offset": 0,                 # Offset in the heuristics list
     "count": 100,                # Number of heuristics returned
     "items":                     # List of heuristics
     [{"id": "AL_HEUR_001",               # Heuristics ID
       "filetype": ".*",                  # Target file type
       "name": "HEURISTICS_NAME",         # Heuristics name
       "description": ""                  # Heuristics description
     },
     ...
    """
    user = kwargs['user']
        
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*").lower()
    
    output = {"total": 0, "offset": offset, "count": length, "items": []}

    if query == "*":
        cleared = []
        for item in HEUR:
            if user and Classification.is_accessible(user['classification'], item['classification']):
                cleared.append(item)
        output["items"] = cleared[offset:offset + length]
        output["total"] = len(cleared)
    elif query:
        filtered = []
        for item in HEUR:
            for key in item:
                if query in item[key].lower() and user \
                        and Classification.is_accessible(user['classification'], item['classification']):
                    filtered.append(deepcopy(item))
                    break

        output["items"] = filtered[offset:offset + length]
        output["total"] = len(filtered)
    
    return make_api_response(output)


@heuristics_api.route("/stats/", methods=["GET"])
@api_login()
def list_heuritics_stats(**kwargs):
    """
    Gather all heuristics stats in system

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"total": 201,                # Total heuristics found
     "timestamp":                 # Timestamp of last heuristics stats
     "items":                     # List of heuristics
     [{"id": "AL_HEUR_001",          # Heuristics ID
       "count": "100",               # Count of times heuristics seen
       "min": 0,                     # Lowest score found
       "avg": 172,                   # Average of all scores
       "max": 780,                   # Highest score found
     },
     ...
    """
    user = kwargs['user']
    output = {"total": 0, "items": [], "timestamp": None}

    heur_blob = STORAGE.get_blob("heuristics_stats")

    if heur_blob:
        cleared = []
        try:
            for k, v in heur_blob["stats"].iteritems():
                heur_id = k
                if heur_id in HEUR_MAP:
                    if user and Classification.is_accessible(user['classification'],
                                                             HEUR_MAP[heur_id]['classification']) and v[0] != 0:
                        cleared.append({
                            "id": heur_id,
                            "count": v[0],
                            "min": v[1],
                            "avg": int(v[2]),
                            "max": v[3],
                            "classification": HEUR_MAP[heur_id]['classification']
                        })
        except AttributeError:
            pass

        output["items"] = cleared
        output["total"] = len(cleared)
        output["timestamp"] = heur_blob["timestamp"]

    return make_api_response(output)
