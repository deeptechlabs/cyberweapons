
import functools
import json
import uuid

from flask import abort, current_app, Blueprint, jsonify, make_response, request, session as flsk_session, Response
from sys import exc_info
from traceback import format_tb

from assemblyline.common.charset import safe_str

from al_ui.config import BUILD_LOWER, BUILD_MASTER, BUILD_NO, DEBUG, AUDIT, AUDIT_LOG, AUDIT_KW_TARGET, LOGGER, \
    RATE_LIMITER, CLASSIFICATION, KV_SESSION
from al_ui.helper.user import login, add_access_control
from al_ui.http_exceptions import AccessDeniedException, QuotaExceededException
from al_ui.config import config, dn_parser
from al_ui.logger import log_with_traceback
from assemblyline.common.isotime import now

API_PREFIX = "/api"
api = Blueprint("api", __name__, url_prefix=API_PREFIX)


####################################
# API Helper func and decorators
# noinspection PyPep8Naming
class api_login(object):
    def __init__(self, require_admin=False, username_key='username',
                 audit=True, required_priv=None, check_xsrf_token=True):
        if required_priv is None:
            required_priv = ["E"]

        self.require_admin = require_admin
        self.username_key = username_key
        self.audit = audit and AUDIT
        self.required_priv = required_priv
        self.check_xsrf_token = check_xsrf_token

    def __call__(self, func):
        @functools.wraps(func)
        def base(*args, **kwargs):
            # Login
            session_id = flsk_session.get("session_id", None)

            if not session_id:
                abort(401)

            session = KV_SESSION.get(session_id)

            if not session:
                abort(401)
            else:
                session = json.loads(session)
                cur_time = now()
                if session.get('expire_at', 0) < cur_time:
                    KV_SESSION.pop(session_id)
                    abort(401)
                else:
                    session['expire_at'] = cur_time + session.get('duration', 3600)

            if request.headers.get("X-Forward-For", None) != session.get('ip', None) or \
                    request.headers.get("User-Agent", None) != session.get('user_agent', None):
                abort(401)

            KV_SESSION.set(session_id, session)

            logged_in_uname = session.get("username", None)

            if not set(self.required_priv).intersection(set(session.get("privileges", []))):
                raise AccessDeniedException("The method you've used to login does not give you access to this API.")

            if "E" in session.get("privileges", []) and self.check_xsrf_token and \
                    session.get('xsrf_token', "") != request.environ.get('HTTP_X_XSRF_TOKEN', ""):
                raise AccessDeniedException("Invalid XSRF token.")

            # Impersonation
            requestor = request.environ.get("HTTP_X_PROXIEDENTITIESCHAIN", None)
            temp_user = login(logged_in_uname)

            # Terms of Service
            if not request.path == "/api/v3/user/tos/%s/" % logged_in_uname:
                if not temp_user.get('agrees_with_tos', False) and config.ui.get("tos", None) is not None:
                    raise AccessDeniedException("Agree to Terms of Service before you can make any API calls.")

            if requestor:
                user = None
                if ("C=" in requestor or "c=" in requestor) and dn_parser:
                    requestor_chain = [dn_parser(x.replace("<", "").replace(">", ""))
                                       for x in requestor.split("><")]
                    requestor_chain.reverse()
                else:
                    requestor_chain = [requestor]

                impersonator = temp_user
                merged_classification = impersonator['classification']
                for as_uname in requestor_chain:
                    user = login(as_uname)
                    if not user:
                        raise AccessDeniedException("One of the entity in the proxied "
                                                    "chain does not exist in our system.")
                    user['classification'] = CLASSIFICATION.intersect_user_classification(user['classification'],
                                                                                          merged_classification)
                    merged_classification = user['classification']
                    add_access_control(user)

                if user:
                    logged_in_uname = "%s(on behalf of %s)" % (impersonator['uname'], user['uname'])
                else:
                    raise AccessDeniedException("Invalid proxied entities chain received.")
            else:
                impersonator = {}
                user = temp_user
            if self.require_admin and not user['is_admin']:
                raise AccessDeniedException("API %s requires ADMIN privileges" % request.path)

            #############################################
            # Special username api query validation
            #
            #    If an API call requests a username, the username as to match
            #    the logged in user or the user has to be ADMIN
            #
            #    API that needs this special validation need to make sure their
            #    variable name for the username is as an optional parameter 
            #    inside 'username_key'. Default: 'username'
            if self.username_key in kwargs:
                if kwargs[self.username_key] != user['uname'] \
                        and not kwargs[self.username_key] == "__global__" \
                        and not kwargs[self.username_key] == "__workflow__" \
                        and not kwargs[self.username_key].lower() == "__current__" \
                        and not user['is_admin']:
                    return make_api_response({}, "Your username does not match requested username", 403)

            if self.audit:
                # noinspection PyBroadException
                try:
                    json_blob = request.json
                    if not isinstance(json_blob, dict):
                        json_blob = {}
                except Exception:
                    json_blob = {}

                params_list = list(args) + \
                    ["%s=%s" % (k, v) for k, v in kwargs.iteritems() if k in AUDIT_KW_TARGET] + \
                    ["%s=%s" % (k, v) for k, v in request.args.iteritems() if k in AUDIT_KW_TARGET] + \
                    ["%s=%s" % (k, v) for k, v in json_blob.iteritems() if k in AUDIT_KW_TARGET]

                if len(params_list) != 0:
                    AUDIT_LOG.info("%s [%s] :: %s(%s)" % (logged_in_uname,
                                                          user['classification'],
                                                          func.func_name,
                                                          ", ".join(params_list)))

            # Save user credential in user kwarg for future reference
            kwargs['user'] = user

            # Check current user quota
            quota_user = impersonator.get('uname', None) or user['uname']
            quota_id = "%s [%s] => %s" % (quota_user, str(uuid.uuid4()), request.path)
            count = int(RATE_LIMITER.inc(quota_user, track_id=quota_id))
            RATE_LIMITER.inc("__global__", track_id=quota_id)

            flsk_session['quota_user'] = quota_user
            flsk_session['quota_id'] = quota_id
            flsk_session['quota_set'] = True

            quota = user.get('api_quota', 10)
            if count > quota:
                if config.ui.enforce_quota:
                    LOGGER.info("User %s was prevented from using the api due to exceeded quota. [%s/%s]" %
                                (quota_user, count, quota))
                    raise QuotaExceededException("You've exceeded your maximum quota of %s " % quota)
                else:
                    LOGGER.info("Quota exceeded for user %s. [%s/%s]" % (quota_user, count, quota))
            else:
                if DEBUG:
                    LOGGER.info("%s's quota is under or equal its limit. [%s/%s]" % (quota_user, count, quota))

            return func(*args, **kwargs)
        base.protected = True
        base.require_admin = self.require_admin
        base.audit = self.audit
        base.required_priv = self.required_priv
        base.check_xsrf_token = self.check_xsrf_token
        return base


def make_api_response(data, err="", status_code=200, cookies=None):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    if type(err) is Exception:
        trace = exc_info()[2]
        err = ''.join(['\n'] + format_tb(trace) +
                      ['%s: %s\n' % (err.__class__.__name__, str(err))]).rstrip('\n')
        log_with_traceback(LOGGER, trace, "Exception", is_exception=True)

    resp = make_response(jsonify({"api_response": data,
                                  "api_error_message": err,
                                  "api_server_version": "%s.%s :: %s" % (BUILD_MASTER, BUILD_LOWER, BUILD_NO),
                                  "api_status_code": status_code}),
                         status_code)

    if isinstance(cookies, dict):
        for k, v in cookies.iteritems():
            resp.set_cookie(k, v)

    return resp


def make_file_response(data, name, size, status_code=200, content_type="application/octet-stream"):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Length"] = size
    response.headers["Content-Disposition"] = 'attachment; filename="%s"' % safe_str(name)
    return response


def stream_file_response(reader, name, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    chunk_size = 65535

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data

    headers = {"Content-Type": 'application/octet-stream',
               "Content-Length": size,
               "Content-Disposition": 'attachment; filename="%s"' % safe_str(name)}
    return Response(generate(), status=status_code, headers=headers)


def make_binary_response(data, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = 'application/octet-stream'
    response.headers["Content-Length"] = size
    return response


def stream_binary_response(reader, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_id = flsk_session.pop("quota_id", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        RATE_LIMITER.dec(quota_user, track_id=quota_id)
        RATE_LIMITER.dec("__global__", track_id=quota_id)

    chunk_size = 4096

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data

    return Response(generate(), status=status_code, mimetype='application/octet-stream')


#####################################
# API list API (API inception)
# noinspection PyUnusedLocal
@api.route("/")
@api_login(audit=False, required_priv=['R', 'W'])
def api_version_list(**kwargs):
    """
    List all available API versions.
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    ["v1", "v2", "v3"]         #List of API versions available
    """
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith("/api/"):
            version = rule.rule[5:].split("/", 1)[0]
            if version not in api_list and version != '':
                # noinspection PyBroadException
                try:
                    int(version[1:])
                except Exception:
                    continue
                api_list.append(version)

    return make_api_response(api_list)


@api.route("/site_map/")
@api_login(require_admin=True, audit=False)
def site_map(**kwargs):
    """
    Check if all pages have been protected by a login decorator
    
    Variables: 
    None
    
    Arguments: 
    unsafe_only                    => Only show unsafe pages
    
    Data Block:
    None
    
    Result example:
    [                                #List of pages dictionary containing...
     {"function": views.default,     #Function name
      "url": "/",                    #Url to page
      "protected": true,             #Is function login protected
      "admin_only": false,           #Is this page only for admins
      "methods": ["GET"]},           #Methods allowed to access the page
    ]
    """
    if not kwargs['user']['is_admin']:
        return make_api_response({}, "Only admins are allowed to view this API", 403)

    pages = []
    for rule in current_app.url_map.iter_rules():
        func = current_app.view_functions[rule.endpoint]
        methods = []
        for item in rule.methods:
            if item != "OPTIONS" and item != "HEAD":
                methods.append(item)
        protected = func.func_dict.get('protected', False)
        admin_only = func.func_dict.get('require_admin', False)
        audit = func.func_dict.get('audit', False)
        priv = func.func_dict.get('required_priv', '')

        if "unsafe_only" in request.args and protected:
            continue

        pages.append({"function": rule.endpoint,
                      "url": rule.rule,
                      "methods": methods,
                      "protected": protected,
                      "admin_only": admin_only,
                      "audit": audit,
                      "req_priv": priv})

    return make_api_response(pages)
