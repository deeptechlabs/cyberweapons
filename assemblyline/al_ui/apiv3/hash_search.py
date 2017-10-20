from flask import request

from assemblyline.common.concurrency import execute_concurrently
from assemblyline.common.importing import module_attribute_by_name
from al_ui.api_base import api_login, make_api_response
from al_ui.apiv3 import core
from al_ui.config import LOGGER, config
from assemblyline.al.datasource.common import hash_type

SUB_API = 'hash_search'

hash_search_api = core.make_subapi_blueprint(SUB_API)
hash_search_api._doc = "Search hashes through multiple data sources"


class SkipDatasource(Exception):
    pass


def create_query_datasource(ds):
    def query_datasource(h, u):
        return {
            'error': None,
            'items': ds.parse(ds.query(h, **u), **u)
        }
    return query_datasource

sources = {}
# noinspection PyBroadException
try:
    for name, settings in config.datasources.iteritems():
        name = name.lower()
        classpath = 'unknown'
        # noinspection PyBroadException
        try:
            classpath = settings['classpath']
            cfg = settings['config']
            if isinstance(cfg, basestring):
                path = cfg
                cfg = config
                for point in path.split('.'):
                    if 'enabled' in cfg:
                        if not cfg['enabled']:
                            raise SkipDatasource()
                    cfg = cfg.get(point)
            cls = module_attribute_by_name(classpath)
            obj = cls(LOGGER, **cfg)
            sources[name] = create_query_datasource(obj)
        except SkipDatasource:
            continue
        except:  # pylint: disable=W0702
            LOGGER.exception(
                "Problem creating %s datasource (%s)", name, classpath
            )
except:  # pylint: disable=W0702
    LOGGER.exception("No datasources")


# noinspection PyUnusedLocal
@hash_search_api.route("/<file_hash>/", methods=["GET"])
@api_login(required_priv=['R'])
def search_hash(file_hash, *args, **kwargs):
    """
    Search for a hash in multiple data sources as configured in the seed.

    Variables:
    value       => Hash to search in the multiple data sources
                   [MD5, SHA1 or SHA256]

    Arguments:(optional)
    db          => | separated list of data sources
    show_timers => Display time it took to query each sources
    max_timeout => Maximum execution time for the call in seconds

    Data Block:
    None

    API call examples:
    /api/v3/hash_search/
    /api/v3/hash_search/123456...654321/?db=nsrl|al&show_timers=true

    Result example:
    {                           # Dictionary of:
        "al": {                   # Data source queried
          "error": null,            # Error message returned by data source
          "items": [                # List of items found in the data source
           {"confirmed": true,        # Is the maliciousness attribution confirmed or not
            "data":                   # Raw data from the data source
            "description": "",        # Description of the findings
            "malicious": false},      # Is the file found malicious or not
          ...
          ]
        },
        ...
    }
    """

    user = kwargs['user']
    if hash_type(file_hash) == "invalid":
        return make_api_response("", "Invalid hash. This API only supports MD5, SHA1 and SHA256.", 400)

    db_list = []
    invalid_sources = []
    db = request.args.get('db', None)
    if db:
        db_list = db.split("|")
        invalid_sources = []
        for x in db_list:
            if x not in sources:
                invalid_sources.append(x)

        for x in invalid_sources:
            db_list.remove(x)

    show_timers = request.args.get('show_timers', False)
    if show_timers:
        show_timers = show_timers.lower() == 'true'

    max_timeout = request.args.get('max_timeout', "2")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except:  # pylint: disable=W0702
        max_timeout = 2.0

    if len(db_list) == 0 and len(invalid_sources) == 0:
        db_list = sources.keys()

    plan = [(sources[x], (file_hash.lower(), user), x) for x in db_list]
    res = execute_concurrently(plan, calculate_timers=show_timers, max_timeout=max_timeout)

    data = {}
    for x in db_list:
        if x not in res:
            if x in res["_timeout_"]:
                data[x] = {"items": [], "error": "Service reached the maximum execution time. [%s seconds]" %
                                                 max_timeout}
            elif x in res["_exception_"]:
                exception = res["_exception_"][x]
                e = "%s: %s" % (exception.__class__.__name__, str(exception))
                data[x] = {"items": [], "error": "Exception occured while querying datasource. [%s]" % e}
            else:
                data[x] = {"items": [], "error": "Service is currently not available."}
        else:
            data[x] = res[x]

    if show_timers:
        data['_timers_'] = res.get("_timers_", {})
    return make_api_response(data)


# noinspection PyUnusedLocal
@hash_search_api.route("/list_data_sources/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def list_data_sources(*args, **kwargs):
    """
    List all available data sources to use the hash_search API

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [ <list of sources> ]
    """
    return make_api_response(sorted(sources.keys()))
