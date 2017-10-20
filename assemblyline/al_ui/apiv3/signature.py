import datetime
import os

from flask import request
from hashlib import md5
from riak import RiakError
from textwrap import dedent

from assemblyline.common.isotime import iso_to_epoch
from assemblyline.al.common import forge
from assemblyline.al.common.remote_datatypes import ExclusionWindow
from assemblyline.al.common.transport.local import TransportLocal
from al_ui.api_base import api_login, make_api_response, make_file_response
from al_ui.apiv3 import core
from al_ui.config import LOGGER, STORAGE, ORGANISATION, YARA_PARSER

SUB_API = 'signature'

Classification = forge.get_classification()

config = forge.get_config()

signature_api = core.make_subapi_blueprint(SUB_API)
signature_api._doc = "Perform operations on signatures"


@signature_api.route("/add/", methods=["PUT"])
@api_login(audit=False, required_priv=['W'])
def add_signature(**kwargs):
    """
    Add a signature to the system and assigns it a new ID
        WARNING: If two person call this method at exactly the
                 same time, they might get the same ID.
       
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    
    Result example:
    {"success": true,      #If saving the rule was a success or not
     "sid": "0000000000",  #SID that the rule was assigned
     "rev": 2 }            #Revision number at which the rule was saved.
    """
    user = kwargs['user']
    new_id = STORAGE.get_last_signature_id(ORGANISATION) + 1
    new_rev = 1
    data = request.json
    
    if not Classification.is_accessible(user['classification'], data['meta'].get('classification',
                                                                                 Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    if not user['is_admin'] and "global" in data['type']:
        return make_api_response("", "Only admins are allowed to add global signatures.", 403)

    sid = "%s_%06d" % (data['meta']['organisation'], new_id)
    data['meta']['id'] = sid
    data['meta']['rule_version'] = new_rev
    data['meta']['creation_date'] = datetime.date.today().isoformat()
    data['meta']['last_saved_by'] = user['uname']
    key = "%sr.%s" % (data['meta']['id'], data['meta']['rule_version'])
    yara_version = data['meta'].get('yara_version', None)
    data['depends'], data['modules'] = \
        YARA_PARSER.parse_dependencies(data['condition'], YARA_PARSER.YARA_MODULES.get(yara_version, None))
    res = YARA_PARSER.validate_rule(data)
    if res['valid']:
        query = "name:{name} AND NOT _yz_rk:{sid}*"
        other = STORAGE.direct_search(
            'signature', query.format(name=data['name'], sid=sid),
            args=[('fl', '_yz_rk'), ('rows', '0')],
        )
        if other.get('response', {}).get('numFound', 0) > 0:
            return make_api_response(
                {"success": False},
                "A signature with that name already exists",
                403
            )
            
        data['warning'] = res.get('warning', None)
        STORAGE.save_signature(key, data)
        return make_api_response({"success": True, "sid": data['meta']['id'], "rev": data['meta']['rule_version']})
    else:
        return make_api_response({"success": False}, res, 403)


# noinspection PyPep8Naming
@signature_api.route("/change_status/<sid>/<rev>/<status>/", methods=["GET"])
@api_login(required_priv=['W'])
def change_status(sid, rev, status, **kwargs):
    """
    [INCOMPLETE]
       - DISABLE OTHER REVISION OF THE SAME SIGNTURE WHEN DEPLOYING ONE
    Change the status of a signature
       
    Variables:
    sid    =>  ID of the signature
    rev    =>  Revision number of the signature
    status  =>  New state
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { "success" : true }      #If saving the rule was a success or not
    """
    DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
    DRAFT_STATUSES = ['STAGING', 'TESTING']
    STALE_STATUSES = ['INVALID']
    user = kwargs['user']
    if status == 'INVALID':
        return make_api_response("",
                                 "INVALID signature status is reserved for service use only.",
                                 403)
    if not user['is_admin'] and status in DEPLOYED_STATUSES:
        return make_api_response("",
                                 "Only admins are allowed to change the signature status to a deployed status.",
                                 403)
    
    key = "%sr.%s" % (sid, rev)
    data = STORAGE.get_signature(key)
    if data:
        if not Classification.is_accessible(user['classification'], data['meta'].get('classification',
                                                                                     Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        if data['meta']['al_status'] in STALE_STATUSES and status not in DRAFT_STATUSES:
            return make_api_response("",
                                     "Only action available while signature in {} status is to change "
                                     "signature to a DRAFT status"
                                     .format(data['meta']['al_status']),
                                     403)

        if data['meta']['al_status'] in DEPLOYED_STATUSES and status in DRAFT_STATUSES:
            return make_api_response("", "You cannot change the status of signature %s r.%s from %s to %s." %
                                     (sid, rev, data['meta']['al_status'], status), 403)

        query = "meta.al_status:{status} AND _yz_rk:{sid}* AND NOT _yz_rk:{key}"
        today = datetime.date.today().isoformat()
        uname = user['uname']

        if status not in ['DISABLED', 'INVALID', 'TESTING']:
            for other in STORAGE.get_signatures(
                STORAGE.list_filtered_signature_keys(
                    query.format(key=key, sid=sid, status=status)
                )
            ):
                other['meta']['al_state_change_date'] = today
                other['meta']['al_state_change_user'] = uname
                other['meta']['al_status'] = 'DISABLED'

                other_sid = other['meta']['id']
                other_rev = other['meta']['rule_version']
                other_key = "%sr.%s" % (other_sid, other_rev)
                STORAGE.save_signature(other_key, other)

        data['meta']['al_state_change_date'] = today
        data['meta']['al_state_change_user'] = uname
        data['meta']['al_status'] = status

        STORAGE.save_signature(key, data)
        return make_api_response({"success": True})
    else:
        return make_api_response("", "Signature not found. (%s r.%s)" % (sid, rev), 404)


# noinspection PyBroadException
def _get_cached_signatures(signature_cache, last_modified, query_hash):
    try:
        if signature_cache.getmtime(query_hash) > iso_to_epoch(last_modified):
            s = signature_cache.get(query_hash)
            return make_file_response(
                s, "al_yara_signatures.yar", len(s), content_type="text/yara"
            )
    except:  # pylint: disable=W0702
        LOGGER.exception('Failed to read cached signatures:')

    return None


@signature_api.route("/download/", methods=["GET"])
@api_login(required_priv=['R'])
def download_signatures(**kwargs):
    """
    Download signatures from the system.
    
    Variables:
    None 
    
    Arguments: 
    query       => SOLR query to filter the signatures
                   Default: All deployed signatures
    safe        => Get a ruleset that will work in yara
                   Default: False
    
    Data Block:
    None
    
    Result example:
    <A .YAR SIGNATURE FILE>
    """
    user = kwargs['user']
    query = request.args.get('query', 'meta.al_status:DEPLOYED')

    safe = request.args.get('safe', "false")
    if safe.lower() == 'true':
        safe = True
    else:
        safe = False

    access = user['access_control']
    last_modified = STORAGE.get_signatures_last_modified()

    query_hash = md5(query + access + last_modified).hexdigest() + ".yar"

    signature_cache = TransportLocal(
        base=os.path.join(config.system.root, 'var', 'cache', 'signatures')
    )

    response = _get_cached_signatures(
        signature_cache, last_modified, query_hash
    )

    if response:
        return response

    with ExclusionWindow(query_hash, 30):
        response = _get_cached_signatures(
            signature_cache, last_modified, query_hash
        )
        if response:
            return response

        keys = STORAGE.list_filtered_signature_keys(query, access_control=access)
        signature_list = STORAGE.get_signatures(keys)
    
        # Sort rules to satisfy dependencies
        duplicate_rules = []
        error_rules = []
        global_rules = []
        private_rules_no_dep = []
        private_rules_dep = []
        rules_no_dep = []
        rules_dep = []

        if safe:
            rules_map = {}
            for s in signature_list:
                name = s.get('name', None)
                if not name:
                    continue

                version = int(s.get('meta', {}).get('rule_version', '1'))

                p = rules_map.get(name, {})
                pversion = int(p.get('meta', {}).get('rule_version', '0'))

                if version < pversion:
                    duplicate_rules.append(name)
                    continue
 
                rules_map[name] = s
            signature_list = rules_map.values()

        name_map = {}
        for s in signature_list:
            if s['type'].startswith("global"):
                global_rules.append(s)
                name_map[s['name']] = True
            elif s['type'].startswith("private"):
                if s['depends'] is None or len(s['depends']) == 0:
                    private_rules_no_dep.append(s)
                    name_map[s['name']] = True
                else:
                    private_rules_dep.append(s)
            else:
                if s['depends'] is None or len(s['depends']) == 0:
                    rules_no_dep.append(s)
                    name_map[s['name']] = True
                else:
                    rules_dep.append(s)

        global_rules = sorted(global_rules, key=lambda k: k['meta']['id'])
        private_rules_no_dep = sorted(private_rules_no_dep, key=lambda k: k['meta']['id'])
        rules_no_dep = sorted(rules_no_dep, key=lambda k: k['meta']['id'])
        private_rules_dep = sorted(private_rules_dep, key=lambda k: k['meta']['id'])
        rules_dep = sorted(rules_dep, key=lambda k: k['meta']['id'])
    
        signature_list = global_rules + private_rules_no_dep
        while private_rules_dep:
            new_private_rules_dep = []
            for r in private_rules_dep:
                found = False
                for d in r['depends']:
                    if not name_map.get(d, False):
                        new_private_rules_dep.append(r)
                        found = True
                        break
                if not found:
                    name_map[r['name']] = True
                    signature_list.append(r)
            
            if private_rules_dep == new_private_rules_dep:
                for x in private_rules_dep:
                    error_rules += [d for d in x["depends"]]

                if not safe:
                    for s in private_rules_dep:
                        name_map[s['name']] = True
                    signature_list += private_rules_dep

                new_private_rules_dep = []
            
            private_rules_dep = new_private_rules_dep

        signature_list += rules_no_dep
        while rules_dep:
            new_rules_dep = []
            for r in rules_dep:
                found = False
                for d in r['depends']:
                    if not name_map.get(d, False):
                        new_rules_dep.append(r)
                        found = True
                        break
                if not found:
                    name_map[r['name']] = True
                    signature_list.append(r)
        
            if rules_dep == new_rules_dep:
                error_rules += [x["name"] for x in rules_dep]
                if not safe:
                    for s in rules_dep:
                        name_map[s['name']] = True
                    signature_list += rules_dep

                new_rules_dep = []

            rules_dep = new_rules_dep    
        # End of sort
    
        error = ""
        if duplicate_rules:
            if safe:
                err_txt = "were skipped"
            else:
                err_txt = "exist"
            error += dedent("""\
            
                // [ERROR] Duplicates rules {msg}:
                //
                //	{rules}
                //
                """).format(msg=err_txt, rules="\n//\t".join(duplicate_rules))
        if error_rules:
            if safe:
                err_txt = "were skipped due to"
            else:
                err_txt = "are"
            error += dedent("""\
            
                // [ERROR] Some rules {msg} missing dependencies:
                //
                //	{rules}
                //
                """).format(msg=err_txt, rules="\n//\t".join(error_rules))
        # noinspection PyAugmentAssignment

        header = dedent("""\
            // Signatures last updated: {last_modified}
            // Signatures matching filter:
            //
            //	{query}
            // {error}
            // Number of rules in file:
            //
            """).format(query=query, error=error, last_modified=last_modified)

        rule_file_bin = header + YARA_PARSER().dump_rule_file(signature_list)
        rule_file_bin = rule_file_bin

        signature_cache.save(query_hash, rule_file_bin)

        return make_file_response(
            rule_file_bin, "al_yara_signatures.yar",
            len(rule_file_bin), content_type="text/yara"
        )


@signature_api.route("/<sid>/<rev>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_signature(sid, rev, **kwargs):
    """
    Get the detail of a signature based of its ID and revision
    
    Variables:
    sid    =>     Signature ID
    rev    =>     Signature revision number
    
    Arguments: 
    None
    
    Data Block:
    None
     
    Result example:
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    """
    user = kwargs['user']
    data = STORAGE.get_signature("%sr.%s" % (sid, rev))
    if data:
        if not Classification.is_accessible(user['classification'],
                                            data['meta'].get('classification',
                                                             Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to view this signature.", 403)
        return make_api_response(data)
    else:
        return make_api_response("", "Signature not found. (%s r.%s)" % (sid, rev), 404)


@signature_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'])
def list_signatures(**kwargs):
    """
    List all the signatures in the system. 
    
    Variables:
    None 
    
    Arguments: 
    offset       => Offset at which we start giving signatures
    length       => Numbers of signatures to return
    filter       => Filter to apply on the signature list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total signatures found
     "offset": 0,                 # Offset in the signature list
     "count": 100,                # Number of signatures returned
     "items": [{                  # List of Signatures:
       "name": "sig_name",          # Signature name    
       "tags": ["PECheck"],         # Signature tags
       "comments": [""],            # Signature comments lines
       "meta": {                    # Meta fields ( **kwargs )
         "id": "SID",                 # Mandatory ID field
         "rule_version": 1 },         # Mandatory Revision field
       "type": "rule",              # Rule type (rule, private rule ...)
       "strings": ['$ = "a"'],      # Rule string section (LIST)
       "condition": ["1 of them"]   # Rule condition section (LIST)
       }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "meta.id:*")
    
    try:
        return make_api_response(STORAGE.list_signatures(start=offset, rows=length, query=query,
                                                         access_control=user['access_control']))
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@signature_api.route("/<sid>/<rev>/", methods=["POST"])
@api_login(required_priv=['W'])
def set_signature(sid, rev, **kwargs):
    """
    [INCOMPLETE]
       - CHECK IF SIGNATURE NAME ALREADY EXISTS
    Update a signature defined by a sid and a rev.
       NOTE: The API will compare they old signature
             with the new one and will make the decision
             to increment the revision number or not. 
    
    Variables:
    sid    =>     Signature ID
    rev    =>     Signature revision number
    
    Arguments: 
    None
    
    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    
    Result example:
    {"success": true,      #If saving the rule was a success or not
     "sid": "0000000000",  #SID that the rule was assigned (Same as provided)
     "rev": 2 }            #Revision number at which the rule was saved.
    """
    user = kwargs['user']
    key = "%sr.%s" % (sid, rev)
    
    old_data = STORAGE.get_signature(key)
    if old_data:
        data = request.json
        if not Classification.is_accessible(user['classification'],
                                            data['meta'].get('classification',
                                                             Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed to change a signature to an "
                                         "higher classification than yours", 403)
    
        if old_data['meta']['al_status'] != data['meta']['al_status']:
            return make_api_response({"success": False}, "You cannot change the signature "
                                                         "status through this API.", 403)
        
        if not Classification.is_accessible(user['classification'],
                                            old_data['meta'].get('classification',
                                                                 Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed to change a signature with "
                                         "higher classification than yours", 403)

        if not user['is_admin'] and "global" in data['type']:
            return make_api_response("", "Only admins are allowed to add global signatures.", 403)

        if YARA_PARSER.require_bump(data, old_data):
            data['meta']['rule_version'] = STORAGE.get_last_rev_for_id(sid) + 1 
            data['meta']['creation_date'] = datetime.date.today().isoformat()
            if 'modification_date' in data['meta']:
                del(data['meta']['modification_date'])
            if 'al_state_change_date' in data['meta']:
                del(data['meta']['al_state_change_date'])
            if 'al_state_change_user' in data['meta']:
                del(data['meta']['al_state_change_user'])
            data['meta']['al_status'] = "TESTING"
            key = "%sr.%s" % (sid, data['meta']['rule_version'])
                
        else:
            data['meta']['modification_date'] = datetime.date.today().isoformat()
            if data['meta']['modification_date'] == data['meta'].get('creation_date', None):
                del(data['meta']['modification_date']) 
        
        data['meta']['last_saved_by'] = user['uname']
        yara_version = data['meta'].get('yara_version', None)
        data['depends'], data['modules'] = \
            YARA_PARSER.parse_dependencies(data['condition'], YARA_PARSER.YARA_MODULES.get(yara_version, None))
        res = YARA_PARSER.validate_rule(data)
        if res['valid']:
            data['warning'] = res.get('warning', None)
            STORAGE.save_signature(key, data)
            return make_api_response({"success": True, "sid": data['meta']['id'], "rev": data['meta']['rule_version']})
        else:
            return make_api_response({"success": False}, res, 403)
    else:
        return make_api_response({"success": False}, "Signature not found. %s" % key, 404)


@signature_api.route("/stats/", methods=["GET"])
@api_login()
def signature_statistics(**kwargs):
    """
    Gather all signatures stats in system

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"total": 201,                # Total heuristics found
     "timestamp":                 # Timestamp of last signatures stats
     "items":                     # List of Signatures
     [{"id": "ORG_000000",           # Signature ID
       "name": "Signature Name"      # Signature name
       "count": "100",               # Count of times signatures seen
       "min": 0,                     # Lowest score found
       "avg": 172,                   # Average of all scores
       "max": 780,                   # Highest score found
     },
     ...
    """
    user = kwargs['user']
    output = {"total": 0, "items": [], "timestamp": None}

    sig_blob = STORAGE.get_blob("signature_stats")

    if sig_blob:
        cleared = []
        try:
            for k, v in sig_blob["stats"].iteritems():
                sig_id, rev = k.rsplit("r.", 1)
                if user and Classification.is_accessible(user['classification'], v[1]):
                    cleared.append({
                        "id": sig_id,
                        "rev": rev,
                        "name": v[0],
                        "count": v[2],
                        "min": v[3],
                        "avg": int(v[4]),
                        "max": v[5],
                        "classification": v[1]
                    })
        except AttributeError:
            pass

        output["items"] = cleared
        output["total"] = len(cleared)
        output["timestamp"] = sig_blob["timestamp"]

    return make_api_response(output)


@signature_api.route("/update_available/", methods=["GET"])
@api_login(required_priv=['R'])
def update_available(**_):  # pylint: disable=W0613
    """
    Check if updated signatures are.

    Variables:
    None

    Arguments:
    last_update        => Epoch time of last update.

    Data Block:
    None

    Result example:
    { "update_available" : true }      # If updated rules are available.
    """
    last_update = iso_to_epoch(request.args.get('last_update'))
    last_modified = iso_to_epoch(STORAGE.get_signatures_last_modified())

    return make_api_response({"update_available": last_modified > last_update})
