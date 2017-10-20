
from flask import request

from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response
from al_ui.config import STORAGE
from assemblyline.al.core.datastore import SearchException

from riak import RiakError

ACCEPTABLE_BUCKETS = ['submission', 'file', 'result', 'error', 'alert', 'signature']
ACCESS_CONTROL_BUCKETS = ['submission', 'file', 'result', 'error', 'alert', 'emptyresult', 'signature']

SUB_API = 'search'
search_api = core.make_subapi_blueprint(SUB_API)
search_api._doc = "Perform search queries"


@search_api.route("/all/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_all(*_, **kwargs):
    """
    Search through all relevant buckets for a given query. Uses
    Apache Solr Search language for query.

    Variables:
    None

    Arguments:
    None

    Data Block:
    {"query": "query",     # Query to search for
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results

    Result example:
    {"files":              # File results
        {"total": 201,       # Total results found
         "offset": 0,        # Offset in the result list
         "count": 100,       # Number of results returned
         "bucket": file,     # Name of the bucket queried
         "items": []},       # List of file results
     "results":            # Result results
         {...},              # Same layout as file results
     "submission":         # Submission results
         {...},              # Same layout as file results
     }
    """
    user = kwargs['user']

    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)

    try:
        return make_api_response(STORAGE.search_all(query, start=offset, rows=length,
                                                    access_control=user['access_control']))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@search_api.route("/alert/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_alerts(*_, **kwargs):
    """
    Search through alert bucket. Uses Apache Solr search
    language.

    Variables:
    None

    Arguments:
    None

    Data Block:
    {"query": "query",     # Query to search for
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results

    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the result list
     "count": 100,       # Number of results returned
     "bucket": file,     # Name of the bucket queried
     "items": []}        # List of results
    """
    user = kwargs['user']

    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)

    return make_api_response(STORAGE.search_alert(query, start=offset, rows=length,
                                                  access_control=user['access_control']))


@search_api.route("/advanced/<bucket>/", methods=["GET"])
@api_login(required_priv=['R'])
def advanced_search(bucket, **kwargs):
    """
    This is a search API that has not been simplified and can leverage the full
    power of SOLR searches.

    You should only use this API if you know what you are doing

    Variables:
    None

    Arguments:
    q   =>  The query you are trying to make

    Optional Arguments:
    *Any arguments the SORL can take in*

    Data Block:
    None

    Result example:
    <<RAW SOLR API OUTPUT>>
    """
    if bucket not in STORAGE.INDEXED_BUCKET_LIST and bucket not in STORAGE.ADMIN_INDEXED_BUCKET_LIST:
        return make_api_response({}, "Bucket '%s' does not exists." % bucket, 404)

    user = kwargs['user']
    query = request.args.get('q', "*")
    df = request.args.get('df', "text")

    if bucket in ACCESS_CONTROL_BUCKETS:
        fq = user['access_control']
    else:
        fq = None

    args = []
    for k in request.args:
        args.extend([(k, v) for v in request.args.getlist(k)])

    return make_api_response(STORAGE.direct_search(bucket, query, args, df=df, __access_control__=fq))


@search_api.route("/deep/<bucket>/", methods=["GET"])
@api_login(required_priv=['R'])
def deep_search(bucket, **kwargs):
    """
    Deep Search through given bucket. This will return all items matching
    the query.
        * Uses Apache Solr search language.
    
    Variables:
    bucket     =>  Buckets to be used to stream the search query from
    
    Arguments: 
    q          => query to search for

    Optional Arguments:
    rows       => maximum result length to return
    fl         => field list to return
    fq         => Filter queries to be applied after the query
    
    Data Block:
    None
     
    Result example:
    { "items": [],      # List of results
      "length": 0 }     # Number of items returned       
    """
    user = kwargs['user']
    
    if bucket not in STORAGE.INDEXED_BUCKET_LIST and bucket not in STORAGE.ADMIN_INDEXED_BUCKET_LIST:
        return make_api_response({}, "Bucket '%s' does not exists." % bucket, 404)

    if bucket not in ACCEPTABLE_BUCKETS:
        return make_api_response("", "You're not allowed to query bucket %s." % bucket, 403)
        
    query = request.args.get('query', None) or request.args.get('q', None)
    if not query:
        return make_api_response({"success": False}, "Please specify a query...", 406) 
    fl = request.args.get('fl', None)
    limit = request.args.get('limit', None) or request.args.get('rows', None)
    fq_list = request.args.getlist('fq')
    if limit:
        limit = int(limit)
    
    out = []
    try:
        for item in STORAGE.stream_search(bucket, query, fl=fl, access_control=user['access_control'], fq=fq_list):
            out.append(STORAGE.result_keys_to_dict(item))
            if limit and len(out) == limit:
                break
        
        return make_api_response({"length": len(out), "items": out})
    except SearchException as ex:
        if "org.apache.solr.search.SyntaxError" in ex.message:
            return make_api_response("", ex.message, 400)
        else:
            return make_api_response("", "You can't just ask for everything. Make your query more precise.", 406)


@search_api.route("/inspect/<bucket>/", methods=["GET"])
@api_login(required_priv=['R'])
def inspect_search(bucket, **kwargs):
    """
    Inspect a search query to find out how much result items are
    going to be returned.
        * Uses Apache Solr search language.
    
    Variables:
    bucket    =>  Buckets to be used to stream the search query from
    
    Arguments: 
    q         => Query to search for

    Optional Arguments:
    fq        => Filter queries to be applied after the query
    
    Data Block:
    None
     
    Result example:
    { count: 0 }     # number of items return by the query
    """
    user = kwargs['user']
    
    if bucket not in STORAGE.INDEXED_BUCKET_LIST and bucket not in STORAGE.ADMIN_INDEXED_BUCKET_LIST:
        return make_api_response({}, "Bucket '%s' does not exists." % bucket, 404)

    if bucket not in ACCEPTABLE_BUCKETS:
        return make_api_response("", "You're not allowed to query bucket %s." % bucket, 403)

    query = request.args.get('query', None) or request.args.get('q', None)
    if not query:
        return make_api_response({"success": False}, "Please specify a query...", 406) 

    args = [('fq', x) for x in request.args.getlist('fq')]
    args.append(('rows', "0"))

    # noinspection PyProtectedMember
    result = STORAGE.direct_search(bucket, query, args, __access_control__=user['access_control'])
    return make_api_response({"count": result.get('response', {}).get("numFound", 0)})


# noinspection PyUnusedLocal
@search_api.route("/fields/", methods=["GET"])
@api_login(required_priv=['R'])
def list_all_available_fields(**kwargs):
    """
    List all available fields for all available buckets

    Variables:
    None

    Arguments:
    bucket  =>     Which specific bucket you want to know the fields for
    full    =>     True/False if you want system buckets to be included
                   Default: False

    Data Block:
    None

    Result example:
    {
        "<<BUCKET_NAME>>": {        # For a given bucket
            "<<FIELD_NAME>>": {      # For a given field
                indexed: True,        # Is the field indexed
                stored: False,        # Is the field stored
                type: string          # What type of data in the field
                },
            ...
            },
        ...
    }
    """
    full = request.args.get('full', "False")
    full = (full.lower() == "true")

    bucket = request.args.get('bucket', None)

    return make_api_response(STORAGE.generate_field_list(full, specific_bucket=bucket))


@search_api.route("/file/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_files(**kwargs):
    """
    Search through file bucket. Uses Apache Solr search 
    language.
    
    Variables:
    None
    
    Arguments: 
    None 
    
    Data Block:
    {"query": "query",     # Query to search for 
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results
    
    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the result list
     "count": 100,       # Number of results returned
     "bucket": file,     # Name of the bucket queried
     "items": []}        # List of results
    """
    user = kwargs['user']
    
    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)

    return make_api_response(STORAGE.search_file(query, start=offset, rows=length,
                                                 access_control=user['access_control']))


@search_api.route("/result/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_results(**kwargs):
    """
    Search through result bucket. Uses Apache Solr search 
    language.
    
    Variables:
    None
    
    Arguments: 
    None 
    
    Data Block:
    {"query": "query",     # Query to search for 
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results
    
    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the result list
     "count": 100,       # Number of results returned
     "bucket": file,     # Name of the bucket queried
     "items": []}        # List of results
    """
    user = kwargs['user']
    
    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)

    return make_api_response(STORAGE.search_result(query, start=offset, rows=length,
                                                   access_control=user['access_control']))


@search_api.route("/signature/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_signatures(**kwargs):
    """
    Search through signature bucket. Uses Apache Solr search 
    language.
    
    Variables:
    None
    
    Arguments: 
    None 
    
    Data Block:
    {"query": "query",     # Query to search for 
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results
    
    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the signature list
     "count": 100,       # Number of results returned
     "bucket": file,     # Name of the bucket queried
     "items": []}        # List of signatures
    """
    user = kwargs['user']
    
    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)
    
    return make_api_response(STORAGE.search_signature(query, start=offset, rows=length,
                                                      access_control=user['access_control']))


@search_api.route("/submission/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def search_submissions(**kwargs):
    """
    Search through submission bucket. Uses Apache Solr search 
    language.
    
    Variables:
    None
    
    Arguments: 
    None 
    
    Data Block:
    {"query": "query",     # Query to search for 
     "offset": 0,          # Offset in the results
     "length": 100}        # Max number of results
    
    Result example:
    {"total": 201,       # Total results found
     "offset": 0,        # Offset in the result list
     "count": 100,       # Number of results returned
     "bucket": file,     # Name of the bucket queried
     "items": []}        # List of results
    """
    user = kwargs['user']
    
    if request.method == "POST":
        offset = request.json.get('offset', 0)
        length = request.json.get('length', 100)
        query = request.json.get('query', "")
    else:
        offset = int(request.args.get('offset', 0))
        length = int(request.args.get('length', 100))
        query = request.args.get('query', "")

    if not query:
        return make_api_response("", "The specified search query is not valid.", 400)
    
    return make_api_response(STORAGE.search_submission(query, start=offset, rows=length,
                                                       access_control=user['access_control']))
