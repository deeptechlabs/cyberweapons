import os
import base64
import shutil

from uuid import uuid4
from flask import request

from assemblyline.common import identify
from assemblyline.common.isotime import now_as_iso
from assemblyline.al.common import forge
from assemblyline.al.common.queue import NamedQueue, MultiQueue
from al_ui.apiv3 import core
from al_ui.config import TEMP_SUBMIT_DIR, STORAGE
from al_ui.api_base import api_login, make_api_response
from al_ui.helper.user import remove_ui_specific_options

config = forge.get_config()

SUB_API = 'ingest'
ingest_api = core.make_subapi_blueprint(SUB_API)
ingest_api._doc = "Ingest files for large volume processing"

ingest = MultiQueue(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    db=config.core.redis.persistent.db)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message/<notification_queue>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_message(notification_queue, **kwargs):
    """
    Get one message on the specified notification queue

    Variables:
    complete_queue       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    {}          # A message
    """
    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port,
                   db=config.core.redis.persistent.db)

    msg = u.pop(blocking=False)

    return make_api_response(msg)


# noinspection PyUnusedLocal
@ingest_api.route("/get_message_list/<notification_queue>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_all_messages(notification_queue, **kwargs):
    """
    Get all messages on the specified notification queue

    Variables:
    complete_queue       => Queue to get the message from

    Arguments:
    None

    Data Block:
    None

    Result example:
    []            # List of messages
    """
    resp_list = []
    u = NamedQueue("nq-%s" % notification_queue,
                   host=config.core.redis.persistent.host,
                   port=config.core.redis.persistent.port,
                   db=config.core.redis.persistent.db)

    while True:
        msg = u.pop(blocking=False)

        if msg is None:
            break

        resp_list.append(msg)

    return make_api_response(resp_list)


# noinspection PyBroadException
@ingest_api.route("/", methods=["POST"])
@api_login(required_priv=['W'])
def ingest_single_file(**kwargs):
    """
    Ingest a single file in the system
        Note:
            Binary and sha256 fields are optional but at least one of them has to be there
            notification_queue, notification_threshold and generate_alert fields are optional
        Note 2:
            The ingest API uses the user's default settings to submit files to the system
            unless these settings are overridden in the 'params' field. Although, there are
            exceptions to that rule. Fields deep_scan, ignore_filtering, ignore_cache,
            ignore_tag are resetted to False because the lead to dangerous behavior in the
            system.

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "name": "file.exe",             # Name of the file
     "binary": "A24AB..==",          # Base64 encoded file binary
     "metadata": {                   # Submission Metadata
         "key": val,                    # Key/Value pair for metadata parameters
         },
     "params": {                     # Submission parameters
         "key": val,                    # Key/Value pair for params that differ from the user's defaults
         },                                 # DEFAULT: /api/v3/user/submission_params/<user>/
     "sha256": "1234...CDEF"         # SHA256 hash of the file
     "srv_spec": {                   # Service specifics parameters
         "Extract": {
             "password": "Try_this_password!@"
             },
         },
     "type": "SUBMISSION_TYPE"       # Required type field,
     "notification_queue": None,     # Name of the notification queue
     "notification_threshold": None, # Threshold for notification
     "generate_alert": False         # Generate an alert in our alerting system or not
    }

    Result example:
    { "success": true }
    """
    user = kwargs['user']
    out_dir = os.path.join(TEMP_SUBMIT_DIR, uuid4().get_hex())

    with forge.get_filestore() as f_transport:
        try:
            data = request.json
            if not data:
                return make_api_response({}, "Missing data block", 400)

            notification_queue = data.get('notification_queue', None)
            if notification_queue:
                notification_queue = "nq-%s" % notification_queue

            notification_threshold = data.get('notification_threshold', None)
            if not isinstance(notification_threshold, int) and notification_threshold:
                return make_api_response({}, "notification_threshold should be and int", 400)

            generate_alert = data.get('generate_alert', False)
            if not isinstance(generate_alert, bool):
                return make_api_response({}, "generate_alert should be a boolean", 400)

            name = data.get("name", None)
            if not name:
                return make_api_response({}, "Filename missing", 400)

            ingest_msg_type = data.get("type", None)
            if not ingest_msg_type:
                return make_api_response({}, "Required type field missing", 400)

            out_file = os.path.join(out_dir, os.path.basename(name))
            try:
                os.makedirs(out_dir)
            except:
                pass

            binary = data.get("binary", None)
            if not binary:
                sha256 = data.get('sha256', None)
                if sha256:
                    if f_transport.exists(sha256):
                        f_transport.download(sha256, out_file)
                    else:
                        return make_api_response({}, "SHA256 does not exist in our datastore", 404)
                else:
                    return make_api_response({}, "Both file binary and sha256 missing", 400)
            else:
                with open(out_file, "wb") as my_file:
                    my_file.write(base64.b64decode(binary))

            overrides = STORAGE.get_user_options(user['uname'])
            overrides['selected'] = overrides['services']
            overrides.update({
                'deep_scan': False,
                "priority": 150,
                "ignore_cache": False,
                "ignore_filtering": False,
                "ignore_tag": False,
            })
            overrides.update(data.get("params", {}))
            overrides.update({
                'description': "[%s] Inspection of file: %s" % (ingest_msg_type, name),
                'generate_alert': generate_alert,
                'max_extracted': 100,
                'max_supplementary': 100,
                'params': data.get("srv_spec", {}),
                'submitter': user['uname'],
            })
            if notification_queue:
                overrides.update({"notification_queue": notification_queue,
                                  "notification_threshold": notification_threshold})

            overrides['priority'] = min(overrides.get("priority", 150), 250)

            metadata = data.get("metadata", {})
            metadata['type'] = ingest_msg_type
            if 'ts' not in metadata:
                metadata['ts'] = now_as_iso()

            digests = identify.get_digests_for_file(out_file)
            digests.pop('path', None)

            sha256 = digests['sha256']
            if not f_transport.exists(sha256):
                f_transport.put(out_file, sha256, location='far')

            msg = {
                "priority": overrides['priority'],
                "type": ingest_msg_type,
                "overrides": remove_ui_specific_options(overrides),
                "metadata": metadata
            }
            msg.update(digests)

            ingest.push(forge.determine_ingest_queue(sha256), msg)

            return make_api_response({"success": True})
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
