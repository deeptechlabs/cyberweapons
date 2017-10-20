
import copy

from assemblyline.common.charset import safe_str
from assemblyline.common.user_defaults import ACCOUNT_DEFAULT, ACCOUNT_USER_MODIFIABLE, SETTINGS_DEFAULT
from assemblyline.al.common import forge
from assemblyline.al.common.remote_datatypes import Hash
from al_ui.config import LOGGER, STORAGE
from al_ui.helper.service import get_default_service_spec, get_default_service_list, simplify_services
from al_ui.http_exceptions import AccessDeniedException, InvalidDataException, QuotaExceededException

config = forge.get_config()
Classification = forge.get_classification()

persistent = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}


###########################
# User Functions
def add_access_control(user):
    user.update(Classification.get_access_control_parts(user.get("classification", Classification.UNRESTRICTED),
                                                        user_classification=True))
    
    gl2_query = " OR ".join(['__access_grp2__:__EMPTY__'] + ['__access_grp2__:"%s"' % x
                                                             for x in user["__access_grp2__"]])
    gl2_query = "(%s) AND " % gl2_query
    
    gl1_query = " OR ".join(['__access_grp1__:__EMPTY__'] + ['__access_grp1__:"%s"' % x
                                                             for x in user["__access_grp1__"]])
    gl1_query = "(%s) AND " % gl1_query
    
    req = list(set(Classification.get_access_control_req()).difference(set(user["__access_req__"])))
    req_query = " OR ".join(['__access_req__:"%s"' % r for r in req])
    if req_query:
        req_query = "-(%s) AND " % req_query
    
    lvl_query = "__access_lvl__:[0 TO %s]" % user["__access_lvl__"]
    
    query = "".join([gl2_query, gl1_query, req_query, lvl_query])
    user['access_control'] = safe_str(query)
     

def check_submission_quota(user, num=1):
    quota_user = user['uname']
    quota = user.get('submission_quota', 5)
    count = num + Hash('submissions-' + quota_user, **persistent).length()
    if count > quota:
        LOGGER.info(
            "User %s exceeded their submission quota. [%s/%s]",
            quota_user, count, quota
        )
        raise QuotaExceededException("You've exceeded your maximum submission quota of %s " % quota)
        

def login(uname, path=None):
    user = STORAGE.get_user_account(uname)
    if not user:
        raise AccessDeniedException("User %s does not exists" % uname)
    
    if not user['is_active']:
        raise AccessDeniedException("User %s is disabled" % uname)
    
    add_access_control(user)
    
    if path:
        user["submenu"] = [{"icon": "glyphicon-user", "active": path.startswith("/account.html"),
                            "link": "/account.html", "title": "Account"},
                           {"icon": "glyphicon-tasks", "active": path.startswith("/dashboard.html"),
                            "link": "/dashboard.html", "title": "Dashboard"},
                           {"icon": "glyphicon-cog", "active": path.startswith("/settings.html"),
                            "link": "/settings.html", "title": "Settings"},
                           {"icon": "glyphicon-log-out", "active": path.startswith("/logout.html"),
                            "link": "/logout.html", "title": "Sign out"}]

        if user['is_admin']:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/admin/") or path.startswith("/dashboard.html") or
                                   path.startswith("/kibana-dash.html"))
            if config.logging.logserver.node:
                user["kibana_dashboards"] = [{"icon": None,
                                              "active": path.startswith("/kibana-dash.html?dash=%s" % x),
                                              "link": "/kibana-dash.html?dash=%s" % x,
                                              "title": "%s" % x.replace("-", " ")}
                                             for x in config.logging.logserver.kibana.dashboards if x != ""]
            user["admin_menu"] = [{"icon": None, "active": path.startswith("/admin/seed.html"),
                                   "link": "/admin/seed.html", "title": "Configuration"},
                                  {"icon": None, "active": path.startswith("/admin/documentation.html"),
                                   "link": "/admin/documentation.html", "title": "Documentation"},
                                  {"icon": None, "active": path.startswith("/admin/errors.html"),
                                   "link": "/admin/errors.html", "title": "Errors viewer"},
                                  {"icon": None, "active": path.startswith("/admin/hosts.html"),
                                   "link": "/admin/hosts.html", "title": "Hosts"},
                                  {"icon": None, "active": path.startswith("/admin/profiles.html"),
                                   "link": "/admin/profiles.html", "title": "Profiles"},
                                  {"icon": None, "active": path.startswith("/admin/provisioning.html"),
                                   "link": "/admin/provisioning.html", "title": "Provisioning"},
                                  {"icon": None, "active": path.startswith("/admin/services.html"),
                                   "link": "/admin/services.html", "title": "Services"},
                                  {"icon": None, "active": path.startswith("/admin/site_map.html"),
                                   "link": "/admin/site_map.html", "title": "Site Map"},
                                  {"icon": None, "active": path.startswith("/admin/users.html"),
                                   "link": "/admin/users.html", "title": "Users"},
                                  {"icon": None, "active": path.startswith("/admin/virtual_machines.html"),
                                   "link": "/admin/virtual_machines.html", "title": "Virtual Machines"}]
        else:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/dashboard.html"))
            user["kibana_dashboards"] = []
            user["admin_menu"] = []

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['allow_2fa'] = config.auth.get('allow_2fa', True)
    user['allow_apikeys'] = config.auth.get('allow_apikeys', True)
    user['allow_u2f'] = config.auth.get('allow_u2f', True)
    user['apikeys'] = [x[0] for x in user.get('apikeys', [])]
    user['c12n_enforcing'] = config.system.classification.definition.enforce
    user['has_password'] = user.pop('password', None) is not None
    user['internal_auth_enabled'] = config.auth.internal.enabled
    user['u2f_enabled'] = len(user.pop('u2f_devices', [])) != 0

    return user


def save_user_account(username, data, user):
    data = validate_settings(data, ACCOUNT_DEFAULT, exceptions=['avatar', 'agrees_with_tos',
                                                                'dn', 'password', 'otp_sk', 'u2f_devices'])

    if username != data['uname']:
        raise AccessDeniedException("You are not allowed to change the username.")

    if username != user['uname'] and not user['is_admin']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    current = STORAGE.get_user_account(username)
    if current:
        current = validate_settings(current, ACCOUNT_DEFAULT,
                                    exceptions=['avatar', 'agrees_with_tos', 'dn', 'password', 'otp_sk', 'u2f_devices'])
        
        if not user['is_admin']:
            for key in current.iterkeys():
                if data[key] != current[key] and key not in ACCOUNT_USER_MODIFIABLE:
                    raise AccessDeniedException("Only Administrators can change the value of the field [%s]." % key)
    else:
        raise InvalidDataException("You cannot save a user that does not exists [%s]." % username)

    if not data['avatar']:
        STORAGE.delete_user(data['uname'] + "_avatar")
    else:
        STORAGE.set_user_avatar(username, data['avatar'])
    data['avatar'] = None
        
    return STORAGE.set_user_account(username, data)


def get_default_user_settings(user):
    out = copy.deepcopy(SETTINGS_DEFAULT)
    out['classification'] = Classification.default_user_classification(user)
    out['services'] = ["Extraction", "Static Analysis", "Filtering", "Antivirus", "Post-Processing"]
    return out


def load_user_settings(user):
    default_settings = copy.deepcopy(SETTINGS_DEFAULT)
    default_settings['classification'] = Classification.default_user_classification(user)
    options = STORAGE.get_user_options(user['uname'])
    srv_list = [x for x in STORAGE.list_services() if x['enabled']]
    if not options:
        def_srv_list = None
        options = default_settings
    else:
        # Make sure all defaults are there
        for key, item in default_settings.iteritems():
            if key not in options:
                options[key] = item
        
        # Remove all obsolete keys
        for key in options.keys():
            if key not in default_settings:
                del options[key]
                
        def_srv_list = options.get('services', None)
    
    options['service_spec'] = get_default_service_spec(srv_list)
    options['services'] = get_default_service_list(srv_list, def_srv_list)

    # Normalize the user's classification
    options['classification'] = Classification.normalize_classification(options['classification'])

    return options


# noinspection PyBroadException
def remove_ui_specific_options(task):
    # Cleanup task object
    task.pop('download_encoding', None)
    task.pop('expand_min_score', None)
    task.pop('hide_raw_results', None)
    task.pop('service_spec', None)
    task.pop('services', None)

    return task


def save_user_settings(username, data):
    data = validate_settings(data, SETTINGS_DEFAULT)
    
    data["service_spec"] = None
    data["services"] = simplify_services(data["services"])
    
    return STORAGE.set_user_options(username, data)


def validate_settings(data, defaults, exceptions=None):
    if not exceptions:
        exceptions = []

    for key in defaults.iterkeys():
        if key not in data:
            data[key] = defaults[key]
        else:
            if key not in exceptions \
                    and not (isinstance(data[key], basestring) and isinstance(defaults[key], basestring)) \
                    and not isinstance(data[key], type(defaults[key])):
                raise Exception("Wrong data type for parameter [%s]" % key)
            else:
                item = data[key]
                if key == 'u2f_devices':
                    continue

                if isinstance(item, basestring):
                    data[key] = item.replace("{", "").replace("}", "")
                elif isinstance(item, list):
                    if len(item) > 0 and isinstance(item[0], basestring):
                        data[key] = [i.replace("{", "").replace("}", "") for i in item]

    to_del = []
    for key in data.iterkeys():
        if key not in defaults:
            to_del.append(key)
            
    for key in to_del:
        del(data[key])
        
    return data
