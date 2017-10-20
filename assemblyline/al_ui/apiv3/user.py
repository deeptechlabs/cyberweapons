
from flask import request

from assemblyline.al.common.security import get_password_hash, check_password_requirements
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.user_defaults import ACCOUNT_DEFAULT
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE, CLASSIFICATION, config
from al_ui.helper.service import ui_to_dispatch_task
from al_ui.helper.user import load_user_settings, save_user_settings, save_user_account, validate_settings
from al_ui.http_exceptions import AccessDeniedException, InvalidDataException
from riak import RiakError

SUB_API = 'user'
user_api = core.make_subapi_blueprint(SUB_API)
user_api._doc = "Manage the different users of the system"

ALLOWED_FAVORITE_TYPE = ["alert", "search", "submission", "signature", "error"]


@user_api.route("/<username>/", methods=["PUT"])
@api_login(require_admin=True)
def add_user_account(username, **_):
    """
    Add a user to the system
    
    Variables: 
    username    => Name of the user to add
    
    Arguments: 
    None
    
    Data Block:
    {                        
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",            # Max classification for user
     "uname": "usertest",        # Username
     "is_admin": false,          # Is the user admin?
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    } 
    
    Result example:
    {
     "success": true             # Saving the user info succeded 
    }
    """
    
    data = request.json

    if "{" in username or "}" in username:
        return make_api_response({"success": False}, "You can't use '{}' in the username", 412)

    if not STORAGE.get_user_account(username):
        new_pass = data.pop('new_pass', None)
        if new_pass:
            if not check_password_requirements(new_pass, strict=config.auth.internal.strict_requirements):
                if config.auth.internal.strict_requirements:
                    error_msg = "Password needs to be 8 characters with at least an uppercase, " \
                                "a lowercase, a number and a special character."
                else:
                    error_msg = "Password needs to be 8 alphanumeric characters."
                return make_api_response({"success": False}, error_msg, 469)
            data['password'] = get_password_hash(new_pass)

        STORAGE.save_user(username, validate_settings(data, ACCOUNT_DEFAULT,
                                                      exceptions=['avatar', 'agrees_with_tos',
                                                                  'dn', 'password', 'otp_sk', 'u2f_devices']))
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, "The username you are trying to add already exists.", 400)


@user_api.route("/favorites/<username>/<favorite_type>/", methods=["PUT"])
@api_login(audit=False)
def add_to_user_favorite(username, favorite_type, **_):
    """
    Add an entry to the user's favorites

    Variables:
    username      => Name of the user you want to add a favorite to
    favorite_type => Type of favorite you want to add

    Arguments:
    None

    Data Block:
    {
     "text": "Name of query",
     "query": "*:*"
    }

    Result example:
    { "success": true }
    """
    if favorite_type not in ALLOWED_FAVORITE_TYPE:
        return make_api_response({}, "%s is not a valid favorite type" % favorite_type, 500)

    data = request.json
    if 'name' not in data or 'query' not in data:
        return make_api_response({}, "Wrong format for favorite.", 500)

    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }
    res_favorites = STORAGE.get_user_favorites(username)
    if res_favorites:
        favorites.update(res_favorites)

    favorites[favorite_type].append(data)

    return make_api_response({"success": STORAGE.set_user_favorites(username, favorites)})


@user_api.route("/tos/<username>/", methods=["GET"])
@api_login()
def agree_with_tos(username, **kwargs):
    """
    Specified user send agreement to Terms of Service

    Variables:
    username    => Name of the user that agrees with tos

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """
    logged_in_user = kwargs['user']
    if logged_in_user['uname'] != username:
        return make_api_response({"success": False},
                                 "You can't agree to Terms Of Service on behalf of someone else!",
                                 400)

    user = STORAGE.get_user_account(username)

    if not user:
        return make_api_response({"success": False}, "User %s does not exist." % username, 403)
    else:
        user['agrees_with_tos'] = now_as_iso()
        if config.ui.get('tos_lockout', False):
            user['is_active'] = False
        STORAGE.save_user(username, user)
        return make_api_response({"success": True})


@user_api.route("/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_account(username, **kwargs):
    """
    Load the user account information.
    
    Variables: 
    username       => Name of the user to get the account info
    
    Arguments: 
    load_avatar    => If exists, this will load the avatar as well
    
    Data Block:
    None
    
    Result example:
    {                        
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",            # Max classification for user
     "uname": "usertest",        # Username
     "is_admin": false,          # Is the user admin?
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    } 
    """
    if username != kwargs['user']['uname'] and not kwargs['user']['is_admin']:
        return make_api_response({}, "You are not allow to view other users then yourself.", 403)

    user = STORAGE.get_user_account(username)
    if not user:
        return make_api_response({}, "User %s does not exists" % username, 404)

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['apikeys'] = [x[0] for x in user.get('apikeys', [])]
    user['has_password'] = user.pop('password', None) is not None
    user['u2f_enabled'] = len(user.pop('u2f_devices', [])) != 0

    if "api_quota" not in user:
        user['api_quota'] = ACCOUNT_DEFAULT.get('api_quota', 10)
    
    if "submission_quota" not in user:
        user['submission_quota'] = ACCOUNT_DEFAULT.get('submission_quota', 5)

    if "load_avatar" in request.args:
        user['avatar'] = STORAGE.get_user_avatar(username)
        
    return make_api_response(user)


@user_api.route("/avatar/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_avatar(username, **_):
    """
    Loads the user's avatar.
    
    Variables: 
    username    => Name of the user you want to get the avatar for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD..."
    """
    avatar = STORAGE.get_user_avatar(username)
    return make_api_response(avatar)


@user_api.route("/favorites/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_favorites(username, **kwargs):
    """
    Loads the user's favorites.

    Variables:
    username    => Name of the user you want to get the avatar for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {                   # Dictionary of
     "<name_of_query>":   # Named queries
        "*:*",              # The actual query to run
     ...
    }
    """
    user = kwargs['user']

    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }
    res_favorites = STORAGE.get_user_favorites(username)

    if res_favorites:
        if username == "__global__" or username != user['uname']:
            for key in favorites.keys():
                for fav in res_favorites[key]:
                    if 'classification' in fav:
                        if CLASSIFICATION.is_accessible(user['classification'], fav['classification']):
                            favorites[key].append(fav)
                    else:
                        favorites[key].append(fav)
        else:
            favorites.update(res_favorites)

    return make_api_response(favorites)


@user_api.route("/settings/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def get_user_settings(username, **kwargs):
    """
    Load the user's settings.
    
    Variables: 
    username    => Name of the user you want to get the settings for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
     "profile": true,               # Should submissions be profiled
     "classification": "",          # Default classification for this user sumbissions
     "description": "",             # Default description for this user's submissions
     "hide_raw_results": false,     # Should you hide raw JSON results?
     "download_encoding": "blah",   # Default encoding for downloaded files
     "expand_min_score": 100,       # Default minimum score to auto-expand sections
     "priority": 1000,              # Default submission priority 
     "service_spec": [],            # Default Service specific parameters
     "ignore_cache": true,          # Should file be reprocessed even if there are cached results
     "groups": [ ... ],             # Default groups selection for the user scans
     "ttl": 30,                     # Default time to live in days of the users submissions
     "services": [ ... ],           # Default list of selected services
     "ignore_tag": false,           # Send file to all service even if file not supported
     "ignore_filtering": false      # Should filtering services by ignored?
    }
    """
    user = kwargs['user']
    
    if username != user['uname']:
        user = STORAGE.get_user_account(username)
    return make_api_response(load_user_settings(user))


@user_api.route("/submission_params/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def get_user_submission_params(username, **kwargs):
    """
    Load the user's default submission params that should be passed to the submit API.
    This is mainly use so you can alter a couple fields and preserve the user
    default values.

    Variables:
    username    => Name of the user you want to get the settings for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "profile": true,               # Should submissions be profiled
     "classification": "",          # Default classification for this user sumbissions
     "description": "",             # Default description for this user's submissions
     "priority": 1000,              # Default submission priority
     "service_spec": [],            # Default Service specific parameters
     "ignore_cache": true,          # Should file be reprocessed even if there are cached results
     "groups": [ ... ],             # Default groups selection for the user scans
     "ttl": 30,                     # Default time to live in days of the users submissions
     "services": [ ... ],           # Default list of selected services
     "ignore_tag": false,           # Send file to all service even if file not supported
     "ignore_filtering": false      # Should filtering services by ignored?
    }
    """
    user = kwargs['user']

    if username != "__CURRENT__" and username != user['uname']:
        user = STORAGE.get_user_account(username)

    params = load_user_settings(user)
    dispatch_task = ui_to_dispatch_task(params, kwargs['user']['uname'])
    dispatch_task['groups'] = user['groups']

    return make_api_response(dispatch_task)


@user_api.route("/list/", methods=["GET"])
@api_login(require_admin=True, audit=False)
def list_users(**_):
    """
    List all users of the system.
    
    Variables:
    None
    
    Arguments: 
    offset        =>  Offset in the user bucket
    length        =>  Max number of user returned
    filter        =>  Filter to apply to the user list
    
    Data Block:
    None
    
    Result example:
    {
     "count": 100,               # Max number of users            
     "items": [{                 # List of user blocks                        
       "name": "Test user",        # Name of the user
       "is_active": true,          # Is the user active?
       "classification": "",            # Max classification for user
       "uname": "usertest",        # Username
       "is_admin": false,          # Is the user admin?
       "avatar": null,             # Avatar (Always null here)
       "groups": ["TEST"]          # Groups the user is member of
       }, ...], 
     "total": 10,                # Total number of users
     "offset": 0                 # Offset in the user bucket
    }
    """
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', None)
    
    try:
        return make_api_response(STORAGE.list_users(start=offset, rows=length, query=query))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@user_api.route("/<username>/", methods=["DELETE"])
@api_login(require_admin=True)
def remove_user_account(username, **_):
    """
    Remove the account specified by the username.
    
    Variables: 
    username       => Name of the user to get the account info
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {                        
     "success": true  # Was the remove successful?
    } 
    """
    remove_list = [username,
                   "%s_avatar" % username,
                   "%s_options" % username,
                   "%s_favorites" % username]
    for key in remove_list:
        STORAGE.delete_user(key)

    return make_api_response({"success": True})


# noinspection PyBroadException
@user_api.route("/favorites/<username>/<favorite_type>/", methods=["DELETE"])
@api_login()
def remove_user_favorite(username, favorite_type, **_):
    """
    Remove a favorite from the user's favorites.

    Variables:
    username       => Name of the user to remove the favorite from
    favorite_type  => Type of favorite to remove

    Arguments:
    None

    Data Block:
    "name_of_favorite"   # Name of the favorite to remove

    Result example:
    {
     "success": true  # Was the remove successful?
    }
    """
    if favorite_type not in ALLOWED_FAVORITE_TYPE:
        return make_api_response({}, "%s is not a valid favorite type" % favorite_type, 500)

    name = request.data or "None"
    try:
        favorites = STORAGE.get_user_favorites(username)
        for fav in favorites[favorite_type]:
            if fav['name'] == name:
                favorites[favorite_type].remove(fav)
    except Exception:
        return make_api_response({}, "Favorite does not exists, (%s)" % name, 404)

    return make_api_response({"success": STORAGE.set_user_favorites(username, favorites)})


@user_api.route("/<username>/", methods=["POST"])
@api_login()
def set_user_account(username, **kwargs):
    """
    Save the user account information.
    
    Variables: 
    username    => Name of the user to get the account info
    
    Arguments: 
    None
    
    Data Block:
    {                        
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",            # Max classification for user
     "uname": "usertest",        # Username
     "is_admin": false,          # Is the user admin?
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    } 
    
    Result example:
    {
     "success": true             # Saving the user info succeded 
    }
    """
    try:
        data = request.json
        new_pass = data.pop('new_pass', None)

        old_user = STORAGE.get_user(username)
        if not old_user:
            return make_api_response({"success": False}, "User %s does not exists" % username, 404)

        data['apikeys'] = old_user.get('apikeys', [])
        data['otp_sk'] = old_user.get('otp_sk', None)
        data['u2f_devices'] = old_user.get('u2f_devices', [])

        if new_pass:
            if not check_password_requirements(new_pass, strict=config.auth.internal.strict_requirements):
                return make_api_response({"success": False},
                                         "Password does not meet minimum password requirements.", 469)
            data['password'] = get_password_hash(new_pass)
            data.pop('new_pass_confirm', None)
        else:
            data['password'] = old_user.get('password', None)

        return make_api_response({"success": save_user_account(username, data, kwargs['user'])})
    except AccessDeniedException, e:
        return make_api_response({"success": False}, e.message, 403)
    except InvalidDataException, e:
        return make_api_response({"success": False}, e.message, 400)


@user_api.route("/avatar/<username>/", methods=["POST"])
@api_login(audit=False)
def set_user_avatar(username, **_):
    """
    Sets the user's Avatar
    
    Variables: 
    username    => Name of the user you want to set the avatar for
    
    Arguments: 
    None
    
    Data Block:
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD..."
    
    Result example:
    {
     "success": true    # Was saving the avatar successful ?
    }
    """
    data = request.json
    if not isinstance(data, str) or not STORAGE.set_user_avatar(username, data):
        make_api_response({"success": False}, "Data block should be a base64 encoded image "
                                              "that starts with 'data:image/<format>;base64,'")
    
    return make_api_response({"success": True})


@user_api.route("/favorites/<username>/", methods=["POST"])
@api_login(audit=False)
def set_user_favorites(username, **_):
    """
    Sets the user's Favorites

    Variables:
    username    => Name of the user you want to set the favorites for

    Arguments:
    None

    Data Block:
    {                   # Dictionary of
     "<name_of_query>":   # Named queries
        "*:*",              # The actual query to run
     ...
    }

    Result example:
    {
     "success": true    # Was saving the favorites successful ?
    }
    """
    data = request.json
    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }

    for key in data:
        if key not in favorites:
            return make_api_response("", err="Invalid favorite type (%s)" % key, status_code=500)

    favorites.update(data)
    return make_api_response({"success": STORAGE.set_user_favorites(username, data)})


@user_api.route("/settings/<username>/", methods=["POST"])
@api_login()
def set_user_settings(username, **_):
    """
    Save the user's settings.
    
    Variables: 
    username    => Name of the user you want to set the settings for
    
    Arguments: 
    None
    
    Data Block:
    {
     "profile": true,              # Should submissions be profiled
     "classification": "",         # Default classification for this user sumbissions
     "description": "",            # Default description for this user's submissions
     "hide_raw_results": false,    # Should you hide raw JSON results?
     "download_encoding": "blah",  # Default encoding for downloaded files
     "expand_min_score": 100,      # Default minimum score to auto-expand sections
     "priority": 1000,             # Default submission priority 
     "service_spec": [],           # Default Service specific parameters
     "ignore_cache": true,         # Should file be reprocessed even if there are cached results
     "groups": [ ... ],            # Default groups selection for the user scans
     "ttl": 30,                    # Default time to live in days of the users submissions
     "services": [ ... ],          # Default list of selected services
     "ignore_tag": false,          # Send file to all service even if file not supported
     "ignore_filtering": false     # Should filtering services by ignored?
    }
    
    Result example:
    {
     "success"': True              # Was saving the params successful ?
    }
    """
    if save_user_settings(username, request.json):
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, "Failed to save user's options", 500)
