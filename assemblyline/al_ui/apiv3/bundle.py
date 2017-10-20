
import os
import uuid

from assemblyline.al.common import forge
from assemblyline.al.common.bundling import create_bundle as bundle_create, import_bundle as bundle_import,\
    SubmissionNotFound, BundlingException, SubmissionAlreadyExist, IncompleteBundle
from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response, stream_file_response
from flask import request

SUB_API = 'bundle'

Classification = forge.get_classification()

bundle_api = core.make_subapi_blueprint(SUB_API)
bundle_api._doc = "Create and restore submission bundles"

WORKING_DIR = "/tmp/al_ui"


# noinspection PyBroadException
@bundle_api.route("/create/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def create_bundle(sid, **kwargs):
    """
    Creates a bundle containing the submission results and the associated files
    
    Variables:
    sid         => ID of the submission to create the bundle for
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/bundle/create/234f334-...-31232/

    Result example:
    -- THE BUNDLE FILE BINARY --
    """
    user = kwargs['user']
    submission = STORAGE.get_submission(sid)
    
    if user and submission and Classification.is_accessible(user['classification'], submission['classification']):
        temp_target_file = None
        try:
            temp_target_file = bundle_create(sid, working_dir=WORKING_DIR)
            f_size = os.path.getsize(temp_target_file)
            return stream_file_response(open(temp_target_file, 'rb'), "%s.al_bundle" % sid, f_size)
        except SubmissionNotFound as snf:
            return make_api_response("", "Submission %s does not exist. [%s]" % (sid, snf.message), 404)
        except BundlingException as be:
            return make_api_response("",
                                     "An error occured while bundling submission %s. [%s]" % (sid, be.message),
                                     404)
        finally:
            try:
                if temp_target_file:
                    os.remove(temp_target_file)
            except:
                pass
    else:
        return make_api_response("", "You are not allowed create a bundle for this submission...", 403)


@bundle_api.route("/import/", methods=["POST"])
@api_login(required_priv=['W'])
def import_bundle(**kwargs):
    """
    Import a bundle file into the system

    Variables:
    None

    Arguments:
    min_classification      => Minimum classification that the files and result from the bundle should get

    Data Block:
    None

    Result example:
    {"success": true}
    """
    min_classification = request.args.get('min_classification', Classification.UNRESTRICTED)

    current_bundle = os.path.join(WORKING_DIR, "%s.bundle" % str(uuid.uuid4()))

    with open(current_bundle, 'wb') as fh:
        fh.write(request.data)

    try:
        bundle_import(current_bundle, working_dir=WORKING_DIR, min_classification=min_classification)
        return make_api_response({'success': True})
    except SubmissionAlreadyExist as sae:
        return make_api_response({'success': False}, err=sae.message, status_code=409)
    except IncompleteBundle as ib:
        return make_api_response({'success': False}, err=ib.message, status_code=400)
