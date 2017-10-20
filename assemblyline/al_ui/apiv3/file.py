from flask import request
from os.path import basename
import re
from assemblyline.common.charset import safe_str

from assemblyline.common.concurrency import execute_concurrently
from assemblyline.common.hexdump import hexdump
from assemblyline.al.common import forge
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response, make_file_response
from al_ui.config import STORAGE, ALLOW_RAW_DOWNLOADS
from al_ui.helper.result import format_result
from al_ui.helper.user import load_user_settings

SUB_API = 'file'

Classification = forge.get_classification()

config = forge.get_config()
context = forge.get_ui_context()
encode_file = context.encode_file

file_api = core.make_subapi_blueprint(SUB_API)
file_api._doc = "Perform operations on files"
FILTER_RAW = ''.join([(len(repr(chr(x))) == 3) and chr(x) or chr(x) == '\\' and chr(x) or chr(x) == "\x09" and chr(x)
                      or chr(x) == "\x0d" and chr(x) or chr(x) == "\x0a" and chr(x) or '.' for x in range(256)])


@file_api.route("/download/<srl>/", methods=["GET"])
@api_login(required_priv=['R'])
def download_file(srl, **kwargs):
    """
    Download the file using the default encoding method. This api
    will force the browser in download mode.
    
    Variables: 
    srl       => A resource locator for the file (sha256)
    
    Arguments: 
    name      => Name of the file to download
    format    => Format to encode the file in
    password  => Password of the password protected zip
    
    Data Block:
    None

    API call example:
    /api/v3/file/download/123456...654321/

    Result example:
    <THE FILE BINARY ENCODED IN SPECIFIED FORMAT>
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        params = load_user_settings(user)
    
        name = request.args.get('name', srl)
        if name == "": 
            name = srl
        else:
            name = basename(name)
        name = safe_str(name)

        file_format = request.args.get('format', params['download_encoding'])
        if file_format == "raw" and not ALLOW_RAW_DOWNLOADS:
            return make_api_response({}, "RAW file download has been disabled by administrators.", 403)

        password = request.args.get('password', None)
        
        with forge.get_filestore() as f_transport:
            data = f_transport.get(srl)

        if not data:
            return make_api_response({}, "The file was not found in the system.", 404)

        data, error, already_encoded = encode_file(data, file_format, name, password)
        if error:
            return make_api_response({}, error['text'], error['code'])

        if file_format != "raw" and not already_encoded:
            name = "%s.%s" % (name, file_format)
    
        return make_file_response(data, name, len(data))
    else:
        return make_api_response({}, "You are not allowed to download this file.", 403)


@file_api.route("/hex/<srl>/", methods=["GET"])
@api_login()
def get_file_hex(srl, **kwargs):
    """
    Returns the file hex representation
    
    Variables: 
    srl       => A resource locator for the file (sha256)
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/file/hex/123456...654321/

    Result example:
    <THE FILE HEX REPRESENTATION>
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)
    
    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(srl)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response(hexdump(data))
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/strings/<srl>/", methods=["GET"])
@api_login()
def get_file_strings(srl, **kwargs):
    """
    Return all strings in a given file

    Variables:
    srl       => A resource locator for the file (sha256)

    Arguments:
    len       => Minimum length for a string

    Data Block:
    None

    Result example:
    <THE LIST OF STRINGS>
    """
    user = kwargs['user']
    hlen = request.args.get('len', "6")
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(srl)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        # Ascii strings
        pattern = "[\x1f-\x7e]{%s,}" % hlen
        string_list = re.findall(pattern, data)

        # UTF-16 strings
        try:
            string_list += re.findall(pattern, data.decode("utf-16", errors="ignore"))
        except UnicodeDecodeError:
            pass

        return make_api_response("\n".join(string_list))
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/raw/<srl>/", methods=["GET"])
@api_login()
def get_file_raw(srl, **kwargs):
    """
    Return the raw values for a file where non-utf8 chars are replaced by DOTs.

    Variables:
    srl       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    Result example:
    <THE RAW FILE>
    """

    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response({}, "The file was not found in the system.", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        with forge.get_filestore() as f_transport:
            data = f_transport.get(srl)

        if not data:
            return make_api_response({}, "This file was not found in the system.", 404)

        return make_api_response(data.translate(FILTER_RAW))
    else:
        return make_api_response({}, "You are not allowed to view this file.", 403)


@file_api.route("/children/<srl>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_children(srl, **kwargs):
    """
    Get the list of children files for a given file

    Variables:
    srl       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/file/children/123456...654321/

    Result example:
    [                           # List of children
     {"name": "NAME OF FILE",       # Name of the children
      "srl": "123..DEF"},           # SRL of the children (SHA256)
    ]
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if file_obj:
        if user and Classification.is_accessible(user['classification'], file_obj['classification']):
            return make_api_response(STORAGE.list_file_childrens(srl, access_control=user["access_control"]))
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)
    else:
        return make_api_response({}, "This file does not exists.", 404)


@file_api.route("/info/<srl>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_information(srl, **kwargs):
    """
    Get information about the file like:
        Hashes, size, frequency count, etc...

    Variables:
    srl       => A resource locator for the file (sha256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/file/info/123456...654321/

    Result example:
    {                                           # File information block
     "ascii": "PK..",                               # First 64 bytes as ASCII
     "classification": "UNRESTRICTED",              # Access control for the file
     "entropy": 7.99,                               # File's entropy
     "hex": "504b...c0b2",                          # First 64 bytes as hex
     "magic": "Zip archive data",                   # File's identification description (from magic)
     "md5": "8f31...a048",                          # File's MD5 hash
     "mime": "application/zip",                     # Mimetype of the file (from magic)
     "seen_count": 7,                               # Number of time we've seen this file
     "seen_first": "2015-03-04T21:59:13.204861Z",   # Time at which we first seen this file
     "seen_last": "2015-03-10T19:42:04.587233Z",    # Last time we've seen the file
     "sha256": "e021...4de2",                       # File's sha256 hash
     "sha1": "354f...fdab",                         # File's sha1 hash
     "size": 3417,                                  # Size of the file
     "ssdeep": "4:Smm...OHY+",                      # File's SSDEEP hash
     "tag": "archive/zip"                           # Type of file that we identified
    }
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if file_obj:
        if user and Classification.is_accessible(user['classification'], file_obj['classification']):
            return make_api_response(file_obj)
        else:
            return make_api_response({}, "You are not allowed to view this file.", 403)
    else:
        return make_api_response({}, "This file does not exists.", 404)


@file_api.route("/result/<srl>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_results(srl, **kwargs):
    """
    Get the all the file results of a specific file.
    
    Variables:
    srl         => A resource locator for the file (SHA256) 
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/file/result/123456...654321/
    
    Result example:
    {"file_info": {},            # File info Block
     "results": {},              # Full result list 
     "errors": {},               # Full error list
     "parents": {},              # List of possible parents
     "childrens": {},            # List of children files
     "tags": {},                 # List tags generated
     "metadata": {},             # Metadata facets results
     "file_viewer_only": True }  # UI switch to disable features
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response({}, "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        output = {"file_info": {}, "results": [], "tags": []}
        plan = [
            (STORAGE.list_file_active_keys, (srl, user["access_control"]), "results"),
            (STORAGE.list_file_parents, (srl, user["access_control"]), "parents"),
            (STORAGE.list_file_childrens, (srl, user["access_control"]), "children"),
            (STORAGE.get_file_submission_meta, (srl, user["access_control"]), "meta"),
        ]
        temp = execute_concurrently(plan)
        active_keys, alternates = temp['results']
        output['parents'] = temp['parents']
        output['childrens'] = temp['children']
        output['metadata'] = temp['meta']

        output['file_info'] = file_obj
        output['results'] = [] 
        output['alternates'] = {}
        res = STORAGE.get_results(active_keys)
        for r in res:
            res = format_result(user['classification'], r, file_obj['classification'])
            if res:
                output['results'].append(res)

        for i in alternates:
            if i['response']['service_name'] not in output["alternates"]:
                output["alternates"][i['response']['service_name']] = []
            i['response']['service_version'] = i['_yz_rk'].split(".", 3)[2].replace("_", ".")
            output["alternates"][i['response']['service_name']].append(i)
        
        output['errors'] = [] 
        output['file_viewer_only'] = True
        
        for res in output['results']:
            # noinspection PyBroadException
            try:
                if "result" in res:
                    if 'tags' in res['result']:
                        output['tags'].extend(res['result']['tags'])
            except:
                pass
        
        return make_api_response(output)
    else:
        return make_api_response({}, "You are not allowed to view this file", 403)


@file_api.route("/result/<srl>/<service>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_results_for_service(srl, service, **kwargs):
    """
    Get the all the file results of a specific file and a specific query.

    Variables:
    srl         => A resource locator for the file (SHA256)

    Arguments:
    all         => if all argument is present, it will return all versions
                    NOTE: Max to 100 results...

    Data Block:
    None

    API call example:
    /api/v3/file/result/123456...654321/service_name/

    Result example:
    {"file_info": {},            # File info Block
     "results": {}}              # Full result list for the service
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    args = [("fl", "_yz_rk"),
            ("sort", "created desc")]
    if "all" in request.args:
        args.append(("rows", "100"))
    else:
        args.append(("rows", "1"))

    if not file_obj:
        return make_api_response([], "This file does not exists", 404)

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        res = STORAGE.direct_search("result", "_yz_rk:%s.%s*" % (srl, service), args,
                                    __access_control__=user["access_control"])['response']['docs']
        keys = [k["_yz_rk"] for k in res]

        results = []
        for r in STORAGE.get_results(keys):
            result = format_result(user['classification'], r, file_obj['classification'])
            if result:
                results.append(result)

        return make_api_response({"file_info": file_obj, "results": results})
    else:
        return make_api_response([], "You are not allowed to view this file", 403)


@file_api.route("/score/<srl>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_score(srl, **kwargs):
    """
    Get the score of the latest service run for a given file.

    Variables:
    srl         => A resource locator for the file (SHA256)

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/file/score/123456...654321/

    Result example:
    {"file_info": {},            # File info Block
     "result_keys": [<keys>]     # List of keys used to compute the score
     "score": 0}                 # Latest score for the file
    """
    user = kwargs['user']
    file_obj = STORAGE.get_file(srl)

    if not file_obj:
        return make_api_response([], "This file does not exists", 404)

    args = [
        ("group", "on"),
        ("group.field", "response.service_name"),
        ("group.format", "simple"),
        ("fl", "result.score,_yz_rk"),
        ("sort", "created desc"),
        ("rows", "100")
    ]

    if user and Classification.is_accessible(user['classification'], file_obj['classification']):
        score = 0
        keys = []
        res = STORAGE.direct_search("result", "_yz_rk:%s*" % srl, args,
                                    __access_control__=user["access_control"])
        docs = res['grouped']['response.service_name']['doclist']['docs']
        for d in docs:
            score += d['result.score']
            keys.append(d["_yz_rk"])

        return make_api_response({"file_info": file_obj, "score": score, "result_keys": keys})
    else:
        return make_api_response([], "You are not allowed to view this file", 403)
