
from flask import session, request
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration

from al_ui.apiv3 import core
from al_ui.api_base import make_api_response, api_login
from al_ui.config import STORAGE, APP_ID

SUB_API = 'u2f'

u2f_api = core.make_subapi_blueprint(SUB_API)
u2f_api._doc = "Perfom 2-Factor authentication with a FIDO U2F USB Key"

U2F_CLIENT_ERROR_MAP = {
    1: "Unspecified error",
    2: "Bad Request - The URL used to access the site may mismatch the seed FQDN value",
    3: "Client configuration not supported",
    4: "Device ineligible or already registered",
    5: "Timed out"
}


@u2f_api.route("/clear/", methods=["GET"])
@api_login(audit=False)
def clear(**kwargs):
    """
    Remove currently configured security token

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
      "success": true
    }
    """
    uname = kwargs['user']['uname']
    user = STORAGE.get_user(uname)
    user.pop('u2f_devices', None)
    STORAGE.save_user(uname, user)
    return make_api_response({'success': True})


@u2f_api.route("/enroll/", methods=["GET"])
@api_login(audit=False)
def enroll(**kwargs):
    """
    Begin registration of a new U2F Security Token

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <U2F_ENROLL_CHALLENGE_BLOCK>
    """
    uname = kwargs['user']['uname']
    user = STORAGE.get_user(uname)
    u2f_devices = user.get('u2f_devices', [])
    current_enroll = begin_registration(APP_ID, u2f_devices)
    session['_u2f_enroll_'] = current_enroll.json

    return make_api_response(current_enroll.data_for_client)


@u2f_api.route("/bind/", methods=["POST"])
@api_login(audit=False)
def bind(**kwargs):
    """
    Complete registration of the new key

    Variables:
    None

    Arguments:
    data    => Response to the enroll challenge

    Data Block:
    None

    Result example:
    {
     "success": True
    }
    """
    uname = kwargs['user']['uname']
    data = request.json
    if "errorCode" in data:
        return make_api_response({'success': False}, err=U2F_CLIENT_ERROR_MAP[data['errorCode']], status_code=400)

    user = STORAGE.get_user(uname)
    current_enroll = session.pop('_u2f_enroll_')

    try:
        device, cert = complete_registration(current_enroll, data, [APP_ID])
    except Exception as e:
        return make_api_response({'success': False}, err=e.message, status_code=400)

    user.setdefault('u2f_devices', []).append(device.json)
    STORAGE.save_user(uname, user)
    return make_api_response({"success": True})


@u2f_api.route("/sign/<username>/", methods=["GET"])
def sign(username, **_):
    """
    Start signin in procedure

    Variables:
    username     user name of the user you want to login with

    Arguments:
    None

    Data Block:
    None

    Result example:
    <U2F_SIGN_IN_CHALLENGE_BLOCK>
    """
    user = STORAGE.get_user(username)
    if not user:
        return make_api_response({'success': False}, err="Bad Request", status_code=400)

    challenge = begin_authentication(APP_ID, user.get('u2f_devices', []))
    session['_u2f_challenge_'] = challenge.json

    return make_api_response(challenge.data_for_client)
