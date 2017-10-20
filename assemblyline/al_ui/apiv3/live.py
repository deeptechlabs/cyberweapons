
from flask import request

from assemblyline.al.common import forge
config = forge.get_config()
from assemblyline.al.common.queue import NamedQueue, reply_queue_name
from assemblyline.al.core.submission import SubmissionWrapper
from al_ui.api_base import api_login, make_api_response
from al_ui.apiv3 import core
from al_ui.config import STORAGE
from assemblyline.al.core.dispatch import DispatchClient

SUB_API = 'live'

Classification = forge.get_classification()

live_api = core.make_subapi_blueprint(SUB_API)
live_api._doc = "Interact with live processing messages"


# noinspection PyUnusedLocal
@live_api.route("/get_message/<wq_id>/", methods=["GET"])
@api_login(required_priv=['W'])
def get_message(wq_id, **kwargs):
    """
    Get a message from a live watch queue. 
    Note: This method is not optimal because it requires the
          UI to pull the information. The prefered method is the
          socket server.
    
    Variables:
    wq_id       => Queue to get the message from
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
     "type": "",         # Type of message
     "err_msg": "",      # Error message
     "status_code": 400, # Status code of the error
     "msg": ""           # Message
    } 
    """
    u = NamedQueue(wq_id)
    
    msg = u.pop(blocking=False)
    
    if msg is None:
        response = {'type': 'timeout', 'err_msg': 'Timeout waiting for a message.', 'status_code': 408, 'msg': None}
    elif msg['status'] == 'STOP':
        response = {'type': 'stop', 'err_msg': None, 'status_code': 200,
                    'msg': "All messages received, closing queue..."}
    elif msg['status'] == 'START':
        response = {'type': 'start', 'err_msg': None, 'status_code': 200, 'msg': "Start listening..."}
    elif msg['status'] == 'OK':
        response = {'type': 'cachekey', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
    elif msg['status'] == 'FAIL':
        response = {'type': 'cachekeyerr', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
    else:
        response = {'type': 'error', 'err_msg': "Unknown message", 'status_code': 500, 'msg': msg}
        
    return make_api_response(response)


# noinspection PyUnusedLocal
@live_api.route("/get_message_list/<wq_id>/", methods=["GET"])
@api_login(required_priv=['W'])
def get_messages(wq_id, **kwargs):
    """
    Get all messages currently on a watch queue. 
    Note: This method is not optimal because it requires the
          UI to pull the information. The prefered method is the
          socket server when possible.
    
    Variables:
    wq_id       => Queue to get the message from
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    []            # List of messages
    """
    resp_list = []
    u = NamedQueue(wq_id)
    
    while True:
        msg = u.pop(blocking=False)
        if msg is None:
            break
        elif msg['status'] == 'STOP':
            response = {'type': 'stop', 'err_msg': None, 'status_code': 200,
                        'msg': "All messages received, closing queue..."}
        elif msg['status'] == 'START':
            response = {'type': 'start', 'err_msg': None, 'status_code': 200, 'msg': "Start listening..."}
        elif msg['status'] == 'OK':
            response = {'type': 'cachekey', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
        elif msg['status'] == 'FAIL':
            response = {'type': 'cachekeyerr', 'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}
        else:
            response = {'type': 'error', 'err_msg': "Unknown message", 'status_code': 500, 'msg': msg}
        
        resp_list.append(response)
            
    return make_api_response(resp_list)


@live_api.route("/outstanding_services/<sid>/", methods=["GET"])
@api_login(required_priv=['W'])
def outstanding_services(sid, **kwargs):
    """
    List outstanding services and the number of file each
    of them still have to process.
    
    Variables:
    sid      => Submission ID
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"MY SERVICE": 1, ... } # Dictionnary of services and number of files
    """
    data = STORAGE.get_submission(sid)
    user = kwargs['user']
    
    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(DispatchClient.get_outstanding_services(sid))
    else:
        return make_api_response({}, "You are not allowed to access this submissions.", 403)


@live_api.route("/setup_watch_queue/<sid>/", methods=["GET"])
@api_login(required_priv=['W'])
def setup_watch_queue(sid, **kwargs):
    """
    Starts a watch queue to get live results
    
    Variables:
    sid      => Submission ID
    
    Arguments: (optional)
    suffix    => suffix to be appended to the queue name
    
    Data Block:
    None
    
    Result example:
    {"wq_id": "c7668cfa-...-c4132285142e"} #ID of the watch queue
    """
    data = STORAGE.get_submission(sid)
    user = kwargs['user']
    
    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        watch_queue = reply_queue_name(request.args.get('suffix', "WQ"))
        SubmissionWrapper.watch(sid, watch_queue)
        return make_api_response({"wq_id": watch_queue})
    else:
        return make_api_response("", "You are not allowed to access this submissions.", 403)
