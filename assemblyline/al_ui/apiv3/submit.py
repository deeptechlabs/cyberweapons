
import base64
import os
import shutil

from uuid import uuid4
from flask import request

from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE, TEMP_SUBMIT_DIR
from al_ui.helper.user import check_submission_quota, get_default_user_settings, load_user_settings, remove_ui_specific_options
from al_ui.helper.service import simplify_services
from assemblyline.al.common import forge
from assemblyline.al.core.submission import SubmissionWrapper
config = forge.get_config()

SUB_API = 'submit'

Classification = forge.get_classification()

submit_api = core.make_subapi_blueprint(SUB_API)
submit_api._doc = "Submit files to the system"

STRIP_KW = ['download_encoding', 'hide_raw_results', 'expand_min_score', 'service_spec', 'services', 'description',
            'sid', 'watch_queue', 'max_score']


# noinspection PyUnusedLocal
@submit_api.route("/checkexists/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def check_srl_exists(*args, **kwargs):
    """
    Check if the the provided Resource locators exist in the
    system or not.
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): 
    ["SRL1", SRL2]    # List of SRLs (SHA256)
    
    Result example:
    {
     "existing": [],  # List of existing SRLs
     "missing": []    # List of missing SRLs
     }
    """
    srls_to_check = request.json
    if type(srls_to_check) != list:
        return make_api_response("", "Expecting a list of SRLs", 403)

    with forge.get_filestore() as f_transport:
        check_results = SubmissionWrapper.check_exists(f_transport, srls_to_check)
    return make_api_response(check_results)


# noinspection PyUnusedLocal
@submit_api.route("/identify/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def identify_supplementary_files(*args, **kwargs):
    """
    Ask the UI to create file entries for supplementary files.

    Variables:
    None

    Arguments:
    None

    Data Block (REQUIRED):
    {
     "1":                                   # File ID
       {"sha256": "982...077",                  # SHA256 of the file
        "classification": "UNRESTRICTED",       # Other KW args to be passed to function
        "ttl": 30 },                            # Days to live for the file
     ...
    }

    Result example:
    {
     "1": {                       # File ID
       "status": "success",         # API result status for the file ("success", "failed")
       "fileinfo": {}               # File information Block
       }, ...
    }
    """
    user = kwargs['user']
    submit_requests = request.json
    submit_results = {}
    user_params = load_user_settings(user)
    for key, submit in submit_requests.iteritems():
        submit['submitter'] = user['uname']
        if 'classification' not in submit:
            submit['classification'] = user_params['classification']
        with forge.get_filestore() as f_transport:
            file_info = SubmissionWrapper.identify(f_transport, STORAGE, **submit)
        if file_info:
            submit_result = {"status": "succeeded", "fileinfo": file_info}
        else:
            submit_result = {"status": "failed", "fileinfo": {}}
        submit_results[key] = submit_result
    return make_api_response(submit_results)


# noinspection PyUnusedLocal
@submit_api.route("/presubmit/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def pre_submission(*args, **kwargs): 
    """
    Perform a presubmit of a list of local files. This is the first
    stage for a batch submit of files.
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): 
    {
     "1":                                       # File ID
       {"sha256": "982...077",                    # SHA256 of the file
        "path": "/local/file/path", },            # Path of the file
     ... }

    Result example:
    {
     "1":                                       # File ID
       {"exists": false,                          # Does the file already exist?
        "succeeded": true,                        # Is the result for this file accurate?
        "filestore": "TransportFTP:transport.al", # File Transport method/url
        "kwargs":                                 # Extra (** kwargs)
          {"path": "/local/file path"},             # Path to the file
        "upload_path": "/remote/upload/path",     # Where to upload if missing
        "sha256": "982...077"},                   # SHA256 of the file
    }
    """
    presubmit_requests = request.json
    presubmit_results = {}
    for key, presubmit in presubmit_requests.iteritems():
        succeeded = True
        presubmit_result = {}
        try:
            with forge.get_filestore() as f_transport:
                presubmit_result = SubmissionWrapper.presubmit(f_transport, **presubmit)
        except Exception as e:
            succeeded = False
            msg = 'Failed to presubmit for {0}:{1}'.format(key, e)
            presubmit_result['error'] = msg
        presubmit_result['succeeded'] = succeeded
        presubmit_results[key] = presubmit_result

    return make_api_response(presubmit_results)


# noinspection PyUnusedLocal
@submit_api.route("/dynamic/<srl>/", methods=["GET"])
@api_login(required_priv=['W'])
def resubmit_for_dynamic(srl, *args, **kwargs): 
    """
    Resubmit a file for dynamic analysis
    
    Variables:
    srl         => Resource locator (SHA256)
    
    Arguments (Optional): 
    copy_sid    => Mimic the attributes of this SID.
    name        => Name of the file for the submission
    
    Data Block:
    None
    
    Result example:
    {
     "submission":{},       # Submission Block
     "request": {},         # Request Block
     "times": {},           # Timing Block
     "state": "submitted",  # Submission state
     "services": {},        # Service selection Block
     "fileinfo": {}         # File information Block
     }
    """
    user = kwargs['user']
    copy_sid = request.args.get('copy_sid', None)
    name = request.args.get('name', srl)
    
    if copy_sid:
        submission = STORAGE.get_submission(copy_sid)
    else:
        submission = None
        
    if submission:
        if not Classification.is_accessible(user['classification'], submission['classification']):
            return make_api_response("", "You are not allowed to re-submit a submission that you don't have access to",
                                     403)
            
        task = {k: v for k, v in submission['submission'].iteritems() if k not in STRIP_KW}
        task.update({k: v for k, v in submission['services'].iteritems() if k not in STRIP_KW})
        task['classification'] = submission['classification']
        
    else:
        params = STORAGE.get_user_options(user['uname'])
        task = {k: v for k, v in params.iteritems() if k not in STRIP_KW}
        task['selected'] = params["services"]
        task['classification'] = params['classification']

    task['sha256'] = srl
    with forge.get_filestore() as f_transport:
        if not f_transport.exists(srl):
            return make_api_response({}, "File %s cannot be found on the server therefore it cannot be resubmitted."
                                         % srl, status_code=404)

        task['path'] = name
        task['submitter'] = user['uname']
        if 'priority' not in task:
            task['priority'] = 500
        task['description'] = "Resubmit %s for Dynamic Analysis" % name
        if "Dynamic Analysis" not in task['selected']:
            task['selected'].append("Dynamic Analysis")

        submit_result = SubmissionWrapper.submit(f_transport, STORAGE, **task)

    return make_api_response(submit_result)


# noinspection PyUnusedLocal
@submit_api.route("/resubmit/<sid>/", methods=["GET"])
@api_login(required_priv=['W'])
def resubmit_submission_for_analysis(sid, *args, **kwargs):
    """
    Resubmit a submission for analysis with the exact same parameters as before

    Variables:
    sid         => Submission ID to re-submit

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "submission":{},       # Submission Block
     "request": {},         # Request Block
     "times": {},           # Timing Block
     "state": "submitted",  # Submission state
     "services": {},        # Service selection Block
     "fileinfo": {}         # File information Block
    }
    """
    user = kwargs['user']
    submission = STORAGE.get_submission(sid)

    if submission:
        if not Classification.is_accessible(user['classification'], submission['classification']):
            return make_api_response("", "You are not allowed to re-submit a submission that you don't have access to",
                                     403)

        task = {k: v for k, v in submission['submission'].iteritems() if k not in STRIP_KW}
        task.update({k: v for k, v in submission['services'].iteritems() if k not in STRIP_KW})
        task['classification'] = submission['classification']
    else:
        return make_api_response({}, "Submission %s does not exists." % sid, status_code=404)

    task['submitter'] = user['uname']
    if 'priority' not in task:
        task['priority'] = 500

    names = []
    for name, _ in submission["files"]:
        names.append(name)

    task['description'] = "Resubmit %s for analysis" % ", ".join(names)

    with forge.get_filestore() as f_transport:
        return make_api_response(SubmissionWrapper.submit_multi(STORAGE, f_transport, submission["files"], **task))


# noinspection PyUnusedLocal
@submit_api.route("/start/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def start_submission(*args, **kwargs): 
    """
    Submit a batch of files at the same time. This assumes that the
    presubmit API was called first to verify if the files are indeed
    already on the system and that the missing files where uploaded 
    using the given transport and upload location returned by the 
    presubmit API. 
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): 
    {
     "1":                         # File ID
       {"sha256": "982...077",      # SHA256 of the file
        "path": "/local/file/path", # Path of the file
        "KEYWORD": ARG, },          # Any other KWARGS for the submission block
     ... }
    
    Result example:
    {
     "1":                         # File ID
       "submission":{},             # Submission Block
       "request": {},               # Request Block
       "times": {},                 # Timing Block
       "state": "submitted",        # Submission state
       "services": {},              # Service selection Block
       "fileinfo": {}               # File information Block
       }, ...
    }
    """
    user = kwargs['user']

    submit_requests = request.json 

    check_submission_quota(user, len(submit_requests))
        
    submit_results = {} 
    user_params = load_user_settings(user)
    for key, submit in submit_requests.iteritems():
        submit['submitter'] = user['uname']
        submit['quota_item'] = True
        path = submit.get('path', './path/missing')
        if 'classification' not in submit:
            submit['classification'] = user_params['classification']
        if 'groups' not in submit:
            submit['groups'] = user['groups']
        if 'description' not in submit:
            submit['description'] = "Inspection of file: %s" % path
        if 'selected'not in submit:
            submit['selected'] = simplify_services(user_params["services"])
        with forge.get_filestore() as f_transport:
            submit_result = SubmissionWrapper.submit(f_transport, STORAGE, **submit)
        submit_results[key] = submit_result
    return make_api_response(submit_results)


# noinspection PyBroadException,PyUnusedLocal
@submit_api.route("/", methods=["POST"])
@api_login(audit=False, required_priv=['W'])
def submit_file(*args, **kwargs):
    """
    Submit a single file inline
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): 
    {
     "name": "file.exe",     # Name of the file
     "binary": "A24AB..==",  # Base64 encoded file binary
     "params": {             # Submission parameters
         "key": val,            # Key/Value pair for params that different then defaults
         },                     # Default params can be fetch at /api/v3/user/submission_params/<user>/
     "srv_spec": {           # Service specifics parameters
         "Extract": {
             "password": "Try_this_password!@"
             },
         }
    }
    
    Result example:
    {
     "submission":{},        # Submission Block
     "times": {},            # Timing Block
     "state": "submitted",   # Submission state
     "services": {},         # Service selection Block
     "fileinfo": {}          # File information Block
     "files": []             # List of submitted files
     "request": {}           # Request detail block
    }
    """
    user = kwargs['user']

    check_submission_quota(user)
        
    out_dir = os.path.join(TEMP_SUBMIT_DIR, uuid4().get_hex())

    try:
        data = request.json
        if not data:
            return make_api_response({}, "Missing data block", 400)
        
        name = data.get("name", None)
        if not name:
            return make_api_response({}, "Filename missing", 400)
        out_file = os.path.join(out_dir, os.path.basename(name))
        
        binary = data.get("binary", None)
        if not binary:
            return make_api_response({}, "File binary missing", 400)
        else:
            try:
                os.makedirs(out_dir)
            except:
                pass
            
            with open(out_file, "wb") as my_file:
                my_file.write(base64.b64decode(binary))

        # Create task object
        task = STORAGE.get_user_options(user['uname'])
        if not task:
            task = get_default_user_settings(user)

        task.update(data.get("params", {}))
        if 'groups' not in task:
            task['groups'] = user['groups']

        task["params"] = data.get("srv_spec", {})
        if 'services' in task and "selected" not in task:
            task["selected"] = task["services"]

        task['quota_item'] = True
        task['submitter'] = user['uname']
        task['sid'] = str(uuid4())
        if not task['description']:
            task['description'] = "Inspection of file: %s" % name
        
        with forge.get_filestore() as f_transport:
            result = SubmissionWrapper.submit_inline(STORAGE, f_transport, [out_file],
                                                     **remove_ui_specific_options(task))

        if result['submission']['sid'] != task['sid']:
            raise Exception('ID does not match what was returned by the dispatcher. Cancelling request...')
        return make_api_response(result)
        
    finally:
        try:
            # noinspection PyUnboundLocalVariable
            os.unlink(out_file)
        except:
            pass

        try:
            shutil.rmtree(out_dir, ignore_errors=True)
        except:
            pass
