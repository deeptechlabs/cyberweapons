
from flask import current_app, Blueprint, request

from al_ui.api_base import api_login, make_api_response

API_PREFIX = "/api/v3"
apiv3 = Blueprint("apiv3", __name__, url_prefix=API_PREFIX)
apiv3._doc = "Api Documentation"
def make_subapi_blueprint(name):
    """ Create a flask Blueprint for a subapi in a standard way. """
    return Blueprint("apiv3." + name, name, url_prefix='/'.join([API_PREFIX, name]))

#####################################
## API DOCUMENTATION
@apiv3.route("/")
@api_login(audit=False, required_priv=['R', 'W'])
def get_api_documentation(*args, **kwargs):
    """
    Full API doc.
    
    Loop through all registered API paths and display their documentation. 
    Returns a list of API definition.
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    [                            # LIST of:
     {'name': "Api Doc",                # Name of the api 
      'path': "/api/path/<variable>/",  # API path
      'ui_only': false,                 # Is UI only API 
      'methods': ["GET", "POST"],       # Allowed HTTP methods
      'description': "API doc.",        # API documentation
      'id': "api_doc",                  # Unique ID for the API
      'function': "apiv3.api_doc",      # Function called in the code
      'protected': False,               # Does the API require login?
      'require_admin': False,           # Is the API only for Admins?
      'complete' : True},               # Is the API stable?
      ...]
    """
    admin_user = kwargs['user']['is_admin']

    api_blueprints = {}
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith(request.path):
            methods = []
            
            for item in rule.methods:
                if item != "OPTIONS" and item != "HEAD":
                    methods.append(item)
            
            func = current_app.view_functions[rule.endpoint]
            require_admin = func.func_dict.get('require_admin', False)
            if not admin_user and require_admin:
                continue

            doc_string = func.func_doc
            func_title = " ".join([x.capitalize() for x in rule.endpoint[rule.endpoint.rindex(".")+1:].split("_")])
            blueprint = rule.endpoint[rule.endpoint.index(".")+1:rule.endpoint.rindex(".")]
            if not blueprint:
                blueprint = "documentation"
            
            if not api_blueprints.has_key(blueprint):
                try:
                    doc = current_app.blueprints[rule.endpoint[:rule.endpoint.rindex(".")]]._doc
                except: 
                    doc = ""
                    
                api_blueprints[blueprint] = doc
            
            try:
                description = "\n".join([x[4:] for x in doc_string.splitlines()])
            except:
                description = "[INCOMPLETE]\n\nTHIS API HAS NOT BEEN DOCUMENTED YET!"
            
            if rule.endpoint == "apiv3.api_doc":
                api_id = "documentation_api_doc"
            else:
                api_id = rule.endpoint.replace("apiv3.", "").replace(".", "_")
                
            api_list.append({
                "protected": func.func_dict.get('protected', False),
                "require_admin": require_admin,
                "name": func_title,
                "id": api_id,
                "function": rule.endpoint,
                "path": rule.rule, "ui_only": rule.rule.startswith("%sui/" % request.path),
                "methods": methods, "description": description,
                "complete": "[INCOMPLETE]" not in description,
                "required_priv": func.func_dict.get('required_priv', "")
            })
    return make_api_response({"apis": api_list, "blueprints": api_blueprints})

