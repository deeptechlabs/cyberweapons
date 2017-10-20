
import functools
import json

from datetime import timedelta
from flask import redirect, render_template, request, abort, current_app, make_response, session as flsk_session
from functools import update_wrapper

from assemblyline.al.common.forge import get_ui_context, get_config

from al_ui.config import DEBUG, STORAGE, BUILD_MASTER, BUILD_LOWER, \
    BUILD_NO, AUDIT, AUDIT_LOG, AUDIT_KW_TARGET, SYSTEM_NAME, get_template_prefix, KV_SESSION

from al_ui.helper.user import login
from al_ui.http_exceptions import AccessDeniedException
from assemblyline.common.isotime import now

config = get_config()
context = get_ui_context()
create_menu = context.create_menu
APP_NAME = context.APP_NAME
TEMPLATE_PREFIX = context.TEMPLATE_PREFIX


#######################################
# Views Helper functions
def redirect_helper(path):
    port = ""
    if request.environ.get("HTTP_SERVER_PORT", None):
        port = ":%s" % request.environ.get("HTTP_SERVER_PORT", None)

    return "%s://%s%s%s" % (request.environ.get("HTTP_SCHEME", "https"),
                            request.environ.get("HTTP_HOST", "localhost"),
                            port, path)


def angular_safe(value):
    if isinstance(value, basestring):
        return value.replace("\\", "%5C").replace("{", "%7B").replace("}", "%7D").replace("'", "%27")
    return value


# noinspection PyPep8Naming
class protected_renderer(object):
    def __init__(self, require_admin=False, load_options=False, audit=True, required_priv=None):
        if required_priv is None:
            required_priv = ["E"]

        self.require_admin = require_admin
        self.load_options = load_options
        self.audit = audit and AUDIT
        self.required_priv = required_priv

    def __call__(self, func):
        @functools.wraps(func)
        def base(*args, **kwargs):
            # Validate User-Agent
            user_agent = request.environ.get("HTTP_USER_AGENT", "Unknown browser")
            if "MSIE 8" in user_agent or "MSIE 9" in user_agent or "MSIE 7" in user_agent or "MSIE 6" in user_agent:
                return redirect(redirect_helper("/unsupported.html"))

            # Create Path
            path = request.path + "?" + request.query_string

            # Login
            try:
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
                    abort(401)

                user = login(logged_in_uname, path)
                if self.require_admin and not user['is_admin']:
                    raise AccessDeniedException("Url '%s' requires ADMIN privileges" % request.path)
            except AccessDeniedException:
                raise

            if self.audit:
                json_blob = request.json
                if not isinstance(json_blob, dict):
                    json_blob = {}
                params_list = list(args) + \
                    ["%s=%s" % (k, v) for k, v in kwargs.iteritems() if k in AUDIT_KW_TARGET] + \
                    ["%s=%s" % (k, v) for k, v in request.args.iteritems() if k in AUDIT_KW_TARGET] + \
                    ["%s=%s" % (k, v) for k, v in json_blob.iteritems() if k in AUDIT_KW_TARGET]
                AUDIT_LOG.info("%s [%s] :: %s(%s)" % (logged_in_uname, user['classification'],
                                                      func.func_name,
                                                      ", ".join(params_list)))

            # Dump Generic KWARGS
            kwargs['build_master'] = "%s.%s" % (BUILD_MASTER, BUILD_LOWER)
            kwargs['user'] = user
            kwargs['user_js'] = json.dumps(user)
            kwargs['debug'] = str(DEBUG).lower()
            kwargs['menu'] = create_menu(user, path)
            kwargs['avatar'] = STORAGE.get_user_avatar(user['uname'])
            kwargs['is_prod'] = SYSTEM_NAME == "production"
            options = STORAGE.get_user_options(user['uname'])
            if not request.path == "/terms.html":
                if not user.get('agrees_with_tos', False) and config.ui.get("tos", None) is not None:
                    return redirect(redirect_helper("/terms.html"))
                if not options and not request.path == "/settings.html":
                    return redirect(redirect_helper("/settings.html?forced"))

            if self.load_options:
                kwargs['options'] = json.dumps(options)

            kwargs["build_no"] = BUILD_NO

            return func(*args, **kwargs)
        base.protected = True
        base.require_admin = self.require_admin
        base.audit = self.audit
        base.required_priv = self.required_priv
        return base


# noinspection PyIncorrectDocstring
def crossdomain(origin=None, methods=None, headers=None, max_age=21600, attach_to_all=True, automatic_options=True):
    """This decorator can be use to allow a page to do cross domain XMLHttpRequests"""
    if methods is not None:
        methods = ", ".join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        # noinspection PyUnresolvedReferences
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))

            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator


def custom_render(template, **kwargs):
    return render_template(get_template_prefix(context, template.replace(".html", "")) + template,
                           app_name=APP_NAME,
                           base_template=get_template_prefix(context, 'base') + "base.html",
                           **kwargs)
