import re

from assemblyline.al.service.base import ServiceBase
from al_ui.api_base import api_login, make_api_response
from assemblyline.al.common import forge
from al_ui.apiv3 import core
from al_ui.config import STORAGE

SUB_API = 'help'
constants = forge.get_constants()
config = forge.get_config()

help_api = core.make_subapi_blueprint(SUB_API)
help_api._doc = "Provide information about the system configuration"


@help_api.route("/classification_definition/")
@api_login(audit=False, check_xsrf_token=False)
def get_classification_definition(**_):
    """
    Return the current system classification definition

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    A parsed classification definition. (This is more for internal use)
    """
    return make_api_response(forge.get_classification().get_parsed_classification_definition())


@help_api.route("/configuration/")
@api_login(audit=False)
def get_system_configuration(**_):
    """
    Return the current system configuration:
        * Max file size
        * Max number of embedded files
        * Extraction's max depth
        * and many others...

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "<CONFIGURATION_ITEM>": <CONFIGURATION_VALUE>
    }
    """
    def get_config_item(parent, cur_item):
        if "." in cur_item:
            key, remainder = cur_item.split(".", 1)
            return get_config_item(parent[key], remainder)
        else:
            return parent.get(cur_item, None)

    cat_map = {}
    stg_map = {}

    for srv in STORAGE.list_services():
        name = srv.get('name', None)
        cat = srv.get('category', None)
        if cat and name:
            temp_cat = cat_map.get(cat, [])
            temp_cat.append(name)
            cat_map[cat] = temp_cat

        stg = srv.get('stage', None)
        if stg and name:
            temp_stg = stg_map.get(stg, [])
            temp_stg.append(name)
            stg_map[stg] = temp_stg

    shareable_config_items = [
        "core.middleman.max_extracted",
        "core.middleman.max_supplementary",
        "services.categories",
        "services.limits.max_extracted",
        "services.limits.max_supplementary",
        "services.stages",
        "services.system_category",
        "submissions.max.priority",
        "submissions.max.size",
        "submissions.ttl",
        "ui.allow_raw_downloads",
        "ui.audit",
        "ui.download_encoding",
        "ui.enforce_quota"
    ]

    out = {}
    for item in shareable_config_items:
        out[item] = get_config_item(config, item)

    out["services.categories"] = [[x, cat_map.get(x, [])] for x in out.get("services.categories", None)]
    out["services.stages"] = [[x, stg_map.get(x, [])] for x in out.get("services.stages", None)]

    return make_api_response(out)


@help_api.route("/constants/")
@api_login(audit=False)
def get_systems_constants(**_):
    """
    Return the current system configuration constants which includes:
        * Priorities
        * File types
        * Service tag types
        * Service tag contexts

    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
        "priorities": {},
        "file_types": [],
        "tag_types": [],
        "tag_contexts": []
    }
    """
    accepts_map = {}
    rejects_map = {}
    default_list = []

    for srv in STORAGE.list_services():
        name = srv.get('name', None)
        if name:
            accept = srv.get('accepts', ".*")
            reject = srv.get('rejects', "empty")
            if accept == ServiceBase.SERVICE_ACCEPTS and reject == ServiceBase.SERVICE_REJECTS:
                default_list.append(name)
            else:
                accepts_map[name] = re.compile(accept)
                rejects_map[name] = re.compile(reject)

    out = {
        "priorities": constants.PRIORITIES,
        "file_types": [[t,
                        sorted([x for x in accepts_map.keys()
                                if re.match(accepts_map[x], t) and not re.match(rejects_map[x], t)])]
                       for t in sorted(constants.RECOGNIZED_TAGS.keys())],
        "tag_types": sorted([x[0] for x in constants.STANDARD_TAG_TYPES]),
        "tag_contexts": sorted([x[0] for x in constants.STANDARD_TAG_CONTEXTS])
    }
    out['file_types'].insert(0, ["*", default_list])

    return make_api_response(out)
