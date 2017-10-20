
import time

from flask import request
from riak import RiakError

from assemblyline.al.common import forge
config = forge.get_config()
from al_ui.api_base import api_login, make_api_response
from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.helper.result import format_result

SUB_API = 'submission'

Classification = forge.get_classification()

submission_api = core.make_subapi_blueprint(SUB_API)
submission_api._doc = "Perform operations on system submissions"


@submission_api.route("/<sid>/", methods=["DELETE"])
@api_login()
def delete_submission(sid, **kwargs):
    """
    INCOMPLETE
    Delete a submission as well as all related 
    files, results and errors
    
    Variables:
    sid         => Submission ID to be deleted
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {success: true}
    """
    user = kwargs['user']
    submission = STORAGE.get_submission(sid)
    
    if submission and user \
            and Classification.is_accessible(user['classification'], submission['classification']) \
            and (submission['submission']['submitter'] == user['uname'] or user['is_admin']):
        with forge.get_filestore() as f_transport:
            STORAGE.delete_submission_tree(sid, transport=f_transport)
        STORAGE.commit_index('submission')
        return make_api_response({"success": True})
    else:
        return make_api_response("", "Your are not allowed to delete this submission.", 403)


# noinspection PyBroadException
@submission_api.route("/<sid>/file/<srl>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def get_file_submission_results(sid, srl, **kwargs):
    """
    Get the all the results and errors of a specific file
    for a specific Submission ID
    
    Variables:
    sid         => Submission ID to get the result for
    srl         => Resource locator to get the result for
    
    Arguments (POST only): 
    extra_result_keys   =>  List of extra result keys to get
    extra_error_keys    =>  List of extra error keys to get
    
    Data Block:
    None
    
    Result example:
    {"errors": [],    # List of error blocks 
     "file_info": {}, # File information block (md5, ...)
     "results": [],   # List of result blocks
     "tags": [] }     # List of generated tags
    """
    user = kwargs['user']
    
    # Check if submission exist
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        # Prepare output
        output = {"file_info": {}, "results": [], "tags": [], "errors": []}
        
        # Extra keys - This is a live mode optimisation
        res_keys = data.get("results", [])
        err_keys = data.get("errors", [])
            
        if request.method == "POST" and request.json is not None and data['state'] != "completed":
            extra_rkeys = request.json.get("extra_result_keys", [])
            extra_ekeys = request.json.get("extra_error_keys", [])
        
            # Load keys 
            res_keys.extend(extra_rkeys)
            err_keys.extend(extra_ekeys)
            
        res_keys = list(set(res_keys))
        err_keys = list(set(err_keys))
    
        # Get File, results and errors
        temp_file = STORAGE.get_file(srl)
        if not Classification.is_accessible(user['classification'], temp_file['classification']):
            return make_api_response("", "You are not allowed to view the data of this file", 403)
        output['file_info'] = temp_file
        
        temp_results = STORAGE.get_results(set([x for x in res_keys if x.startswith(srl)]))
        results = []
        for r in temp_results:
            r = format_result(user['classification'], r, temp_file['classification'])
            if r:
                results.append(r)
        output['results'] = results 

        output['errors'] = STORAGE.get_errors(set([x for x in err_keys if x.startswith(srl)]))
        output['metadata'] = STORAGE.get_file_submission_meta(srl, user["access_control"])
        
        # Generate tag list
        temp = {}
        for res in output['results']:
            try:
                if res.has_key('result'):
                    if res['result'].has_key('tags'):
                        temp.update({"__".join([v["type"], v['value']]): v for v in res['result']['tags']})
            except:
                pass
        
        output["tags"] = temp.values()
        
        return make_api_response(output)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/tree/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_tree(sid, **kwargs):
    """
    Get the file hierarchy of a given Submission ID. This is
    an N deep recursive process but is limited to the max depth
    set in the system settings.
    
    Variables:
    sid         => Submission ID to get the tree for
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/submission/tree/12345678-1234-1234-1234-1234567890AB/
    
    Result example:
    {                                # Dictionary of file blocks
     "1f...11": {                    # File SRL (sha256)
       "score": 923,                 # Score for the file
       "name": ["file.exe",...]      # List of possible names for the file
       "children": {...}             # Dictionary of children file blocks
       }, ...
  
    """
    user = kwargs['user']
    
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        output = STORAGE.create_file_tree(data)
        return make_api_response(output)
    else: 
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/full/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_full_results(sid, **kwargs):
    """
    Get the full results for a given Submission ID. The difference
    between this and the get results API is that this one gets the
    actual values of the result and error keys instead of listing 
    the keys.
    
    Variables:
    sid         => Submission ID to get the full results for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"classification": "UNRESTRICTIED"  # Access control for the submission
     "error_count": 0,                  # Number of errors in this submission
     "errors": [],                      # List of error blocks (see Get Service Error)
     "file_count": 4,                   # Number of files in this submission
     "files": [                         # List of submitted files
       ["FNAME", "SRL"], ...],              # Each file = List of name/srl
     "file_infos": {                    # Dictionary of fil info blocks
       "234...235": <<FILE_INFO>>,          # File in block
       ...},                                # Keyed by file's SRL
     "file_tree": {                     # File tree of the submission
       "333...7a3": {                       # File tree item
        "children": {},                         # Recursive children of file tree item
        "name": ["file.exe",...]                # List of possible names for the file
        "score": 0                              # Score of the file
       },, ...},                            # Keyed by file's SRL
     "missing_error_keys": [],          # Errors that could not be fetched from the datastore
     "missing_result_keys": [],         # Results that could not be fetched from the datastore
     "results": [],                     # List of Results Blocks (see Get Service Result)
     "services": {                      # Service Block
       "selected": ["mcafee"],              # List of selected services
       "params": {},                        # Service specific parameters
       "excluded": []                       # List of excluded services
       },
     "state": "completed",              # State of the submission
     "submission": {                    # Submission Block
       "profile": true,                     # Should keep stats about execution?
       "description": "",                   # Submission description
       "ttl": 30,                           # Submission days to live
       "ignore_filtering": false,           # Ignore filtering services?
       "priority": 1000,                    # Submission priority, higher = faster
       "ignore_cache": true,                # Force reprocess even is result exist?
       "groups": ["group", ...],            # List of groups with access
       "sid": "ab9...956",                  # Submission ID
       "submitter": "user",                 # Uname of the submitter
       "max_score": 1422,                   # Score of highest scoring file
       "ignore_tag": false },               # Send all files to all service?
     "times": {                         # Timing block
       "completed": "2014-...",             # Completed time
       "submitted": "2014-..."              # Submitted time
       }
    }
    """
    max_retry = 10

    def get_results(keys):
        out = {}
        res = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            res.update(STORAGE.get_results_dict(keys))
            keys = [x for x in keys if x not in res]
            retry += 1

        results = {}
        for k, v in res.iteritems():
            file_info = data['file_infos'].get(k[:64], None)
            if file_info:
                v = format_result(user['classification'], v, file_info['classification'])
                if v:
                    results[k] = v

        out["results"] = results
        out["missing_result_keys"] = keys

        return out

    def get_errors(keys):
        out = {}
        err = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            err.update(STORAGE.get_errors_dict(keys))
            keys = [x for x in err_keys if x not in err]
            retry += 1

        out["errors"] = err
        out["missing_error_keys"] = keys

        return out

    def get_file_infos(keys):
        infos = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            infos.update(STORAGE.get_files_dict(keys))
            keys = [x for x in keys if x not in infos]
            retry += 1

        return infos

    def recursive_flatten_tree(tree):
        srls = []

        for key, val in tree.iteritems():
            srls.extend(recursive_flatten_tree(val.get('children', {})))
            if key not in srls:
                srls.append(key)

        return list(set(srls))

    user = kwargs['user']
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        res_keys = data.get("results", [])
        err_keys = data.get("errors", [])

        data['file_tree'] = STORAGE.create_file_tree(data)
        data['file_infos'] = get_file_infos(recursive_flatten_tree(data['file_tree']))
        data.update(get_results(res_keys))
        data.update(get_errors(err_keys))

        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_submission(sid, **kwargs):
    """
    Get the submission details for a given Submission ID
    
    Variables:
    sid         => Submission ID to get the details for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"files": [                 # List of source files
       ["FNAME", "SRL"], ...],    # Each file = List of name/srl
     "errors": [],              # List of error keys (SRL.ServiceName)
     "submission": {            # Submission Block
       "profile": true,           # Should keep stats about execution?
       "description": "",         # Submission description
       "ttl": 30,                 # Submission days to live
       "ignore_filtering": false, # Ignore filtering services? 
       "priority": 1000,          # Submission priority, higher = faster
       "ignore_cache": true,      # Force reprocess even is result exist?
       "groups": ["group", ...],  # List of groups with access   
       "sid": "ab9...956",        # Submission ID
       "submitter": "user",        # Uname of the submitter
       "max_score": 1422,         # Score of highest scoring file
       "ignore_tag": false },     # Send all files to all service?
     "results": [],             # List of Results keys (SRL.ServiceName.Version.Config)
     "times": {                 # Timing block
       "completed": "2014-...",   # Completed time
       "submitted": "2014-..."    # Submitted time
       }, 
     "state": "completed",      # State of the submission
     "services": {              # Service Block
       "selected": ["mcafee"],    # List of selected services
       "params": {},              # Service specific parameters
       "excluded": []             # List of excluded services
       }
    }
    """
    user = kwargs['user']
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/summary/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_summary(sid, **kwargs):
    """
    Retrieve the executive summary of a given submission ID. This
    is a MAP of tags to SRL combined with a list of generated Tags.
    
    Variables:
    sid         => Submission ID to get the summary for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"map": {                # Map of TAGS to SRL
       "TYPE__VAL": [          # Type and value of the tags
         "SRL"                   # List of related SRLs
         ...],
       "SRL": [                # SRL
         "TYPE__VAL"             # List of related type/value
         ...], ... } 
     "tags": {               # Dictionary of tags        
       "TYPE": {               # Type of tag
         "VALUE": {              # Value of the tag
           "usage": "",            # Usage
           "classification": ""    # Classification
           }, ...
         }, ...
    }
    """
    user = kwargs['user']
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if user and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(STORAGE.create_summary(data, user))
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


# noinspection PyUnusedLocal
@submission_api.route("/is_completed/<sid>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def is_submission_completed(sid, **kwargs):
    """
    Check if a submission is completed
    
    Variables:
    sid         =>  Submission ID to lookup
    
    Arguments: 
    None 
    
    Data Block:
    None
    
    Result example:
    True/False
    """
    data = STORAGE.get_submission(sid)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)

    return make_api_response(data.get("state", "submitted") == "completed")


@submission_api.route("/list/group/<group>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_submissions_for_group(group, **kwargs):
    """
    List all submissions of a given group.
    
    Variables:
    None
    
    Arguments: 
    offset       => Offset at which we start giving submissions
    length       => Numbers of submissions to return
    filter       => Filter to apply to the submission list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total results found
     "offset": 0,                 # Offset in the result list
     "count": 100,                # Number of results returned
     "items": [                   # List of submissions
       {"submission": {             # Submission Block
          "description": "",          # Description of the submission
          "sid": "ad2...234",         # Submission ID
          "groups": "GROUP",          # Accessible groups
          "ttl": "30",                # Days to live
          "submitter": "user",        # ID of the submitter
          "max_score": "1422"},       # Max score of all files
        "times": {                  # Timing
          "submitted":                # Time submitted
            "2014-06-17T19:20:19Z"}, 
        "state": "completed"        # State of the submission
    }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")
    
    if group == "ALL":
        group = "*"
    
    try:
        return make_api_response(STORAGE.list_submissions_group(group, start=offset, rows=length, qfilter=query,
                                                                access_control=user['access_control']))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@submission_api.route("/list/user/<username>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_submissions_for_user(username, **kwargs):
    """
    List all submissions of a given user.
    
    Variables:
    None
    
    Arguments: 
    offset       => Offset at which we start giving submissions
    length       => Numbers of submissions to return
    filter       => Filter to apply to the submission list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total results found
     "offset": 0,                 # Offset in the result list
     "count": 100,                # Number of results returned
     "items": [                   # List of submissions
       {"submission": {             # Submission Block
          "description": "",          # Description of the submission
          "sid": "ad2...234",         # Submission ID
          "groups": "GROUP",          # Accessible groups
          "ttl": "30",                # Days to live
          "submitter": "user",        # ID of the submitter
          "max_score": "1422"},       # Max score of all files
        "times": {                  # Timing
          "submitted":                # Time submitted
            "2014-06-17T19:20:19Z"}, 
        "state": "completed"        # State of the submission
    }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")
    
    account = STORAGE.get_user_account(username)
    if not account: 
        return make_api_response("", "User %s does not exists." % username, 404)
        
    try:
        return make_api_response(STORAGE.list_submissions(username, start=offset, rows=length, qfilter=query,
                                                          access_control=user['access_control']))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise
