
from flask import request
from assemblyline.al.common import forge, queue
from assemblyline.al.core.datastore import SearchException
from al_ui.apiv3 import core
from al_ui.config import STORAGE
from al_ui.api_base import api_login, make_api_response
from riak import RiakError

DATABASE_NUM = 4
SUB_API = 'alert'
QUEUE_PRIORITY = -2

Classification = forge.get_classification()

alert_api = core.make_subapi_blueprint(SUB_API)
alert_api._doc = "Perform operations on alerts"


@alert_api.route("/<alert_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_alert(alert_key, **kwargs):
    """
    Get the alert details for a given alert key
    
    Variables:
    alert_key         => Alert key to get the details for
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v3/alert/1234567890/

    Result example:
    {
        KEY: VALUE,   # All fields of an alert in key/value pair
    }
    """
    user = kwargs['user']
    data = STORAGE.get_alert(alert_key)
    
    if user and data and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to see this alert...", 403)


@alert_api.route("/statistics/", methods=["GET"])
@api_login()
def alerts_statistics(**kwargs):
    """
    Load facet statistics for the alerts matching the query.

    Variables:
    None

    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.get_alert_statistics(query, access_control=user['access_control'],
                                                              fq_list=filter_queries,
                                                              start_time=start_time,
                                                              time_slice=time_slice))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/labels/", methods=["GET"])
@api_login()
def alerts_labels(**kwargs):
    """
    Run a facet search to find the different labels matching the query.

    Variables:
    None

    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.get_alert_statistics(query, access_control=user['access_control'],
                                                              fq_list=filter_queries,
                                                              start_time=start_time,
                                                              time_slice=time_slice,
                                                              field_list=['label']).get('label', []))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/priorities/", methods=["GET"])
@api_login()
def alerts_priorities(**kwargs):
    """
    Run a facet search to find the different priorities matching the query.

    Variables:
    None

    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.get_alert_statistics(query, access_control=user['access_control'],
                                                              fq_list=filter_queries,
                                                              start_time=start_time,
                                                              time_slice=time_slice,
                                                              field_list=['priority']).get('priority', []))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/statuses/", methods=["GET"])
@api_login()
def alerts_statuses(**kwargs):
    """
    Run a facet search to find the different statuses matching the query.

    Variables:
    None

    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)

    Data Block:
    None

    Result example:

    """
    user = kwargs['user']

    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.get_alert_statistics(query, access_control=user['access_control'],
                                                              fq_list=filter_queries,
                                                              start_time=start_time,
                                                              time_slice=time_slice,
                                                              field_list=['status']).get('status', []))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'])
def list_alerts(**kwargs):
    """
    List all alert in the system (per page)
    
    Variables:
    None
    
    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    offset       => Offset at which we start giving alerts
    length       => Numbers of alerts to return
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)
    
    Data Block:
    None

    API call example:
    /api/v3/alert/list/

    Result example:
    {"total": 201,                # Total alerts found
     "offset": 0,                 # Offset in the alert list
     "count": 100,                # Number of alerts returned
     "items": []                  # List of alert blocks
    }
    """
    user = kwargs['user']
    
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.list_alerts(query, start=offset, rows=length,
                                                     access_control=user['access_control'],
                                                     fq_list=filter_queries,
                                                     start_time=start_time,
                                                     time_slice=time_slice))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/grouped/<field>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_grouped_alerts(field, **kwargs):
    """
    List all alert grouped by a given field

    Variables:
    None

    Arguments:
    start_time   => Time offset at which to list alerts
    time_slice   => Length after the start time that we query
    offset       => Offset at which we start giving alerts
    length       => Numbers of alerts to return
    filter       => Filter to apply to the alert list
    fq           => Post filter queries (you can have multiple of those)

    Data Block:
    None

    API call example:
    /api/v3/alert/grouped/start_time/

    Result example:
    {"total": 201,                # Total alerts found
     "offset": 0,                 # Offset in the alert list
     "count": 100,                # Number of alerts returned
     "items": [],                 # List of alert blocks
     "start_time": "2015-05..."   # UTC timestamp for future query (ISO Format)
    }
    """
    user = kwargs['user']

    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*")
    if not query:
        query = "*"
    start_time = request.args.get('start_time', None)
    time_slice = request.args.get('time_slice', None)
    filter_queries = [x for x in request.args.getlist("fq") if x != ""]

    try:
        return make_api_response(STORAGE.list_grouped_alerts(query, field, start=offset, rows=length,
                                                             start_time=start_time,
                                                             time_slice=time_slice,
                                                             access_control=user['access_control'],
                                                             fq_list=filter_queries,
                                                             time_offset=-300.0))
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)
    except RiakError, e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise


@alert_api.route("/label/<alert_id>/<labels>/", methods=["GET"])
@api_login(required_priv=['W'])
def add_labels(alert_id, labels, **kwargs):
    """
    Add one or multiple labels to a given alert

    Variables:
    alert_id     => ID of the alert to add the label to
    labels       => List of labels to add as comma separated string

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/alert/label/1234567890/EMAIL/

    Result example:
    {"success": true,
     "event_id": 0}
    """
    user = kwargs['user']
    labels = set(labels.upper().split(","))

    alert = STORAGE.get_alert(alert_id)

    if not alert:
        return make_api_response({"success": False, "event_id": None},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    cur_label = set(alert.get('label', []))
    if labels.difference(labels.intersection(cur_label)):
        cur_label = cur_label.union(labels)
        alert['label'] = list(cur_label)
        STORAGE.save_alert(alert_id, alert)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Alert already has labels %s" % ", ".join(labels),
                                 status_code=403)


@alert_api.route("/label/batch/<labels>/", methods=["GET"])
@api_login()
def add_labels_by_batch(labels, **kwargs):
    """
    Apply labels to all alerts matching the given filters using a background process

    Variables:
    labels       => List of labels to add as comma separated string

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    start     =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v3/alert/label/batch/EMAIL/?q=protocol:SMTP

    Result example:
    { "status": "QUEUED" }
    """
    action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
    labels = set(labels.upper().split(","))

    user = kwargs['user']
    q = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not q and not fq:
        return make_api_response({"success": False,
                                  "event_id": None},
                                 err="You need to at least provide a query to filter the data", status_code=400)
    if not q:
        q = fq.pop(0)
    tc = request.args.get('tc', None)
    start = request.args.get('start', None)

    msg = {
        "user": user['uname'],
        "action": "batch_workflow",
        "query": q,
        "tc": tc,
        "start": start,
        "fq": fq,
        "label": list(labels),
        "queue_priority": QUEUE_PRIORITY
    }

    action_queue.push(QUEUE_PRIORITY, msg)

    return make_api_response({"status": "QUEUED"})


@alert_api.route("/priority/<alert_id>/<priority>/", methods=["GET"])
@api_login(required_priv=['W'])
def change_priority(alert_id, priority, **kwargs):
    """
    Change the priority of a given alert

    Variables:
    alert_id      => ID of the alert to change the priority
    priority      => New priority for the alert

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/alert/priority/1234567890/MALICIOUS/

    Result example:
    {"success": true,
     "event_id": 0}
    """
    user = kwargs['user']
    priority = priority.upper()

    alert = STORAGE.get_alert(alert_id)

    if not alert:
        return make_api_response({"success": False, "event_id": None},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    if priority != alert.get('priority', None):
        alert['priority'] = priority
        STORAGE.save_alert(alert_id, alert)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Alert already has priority %s" % priority,
                                 status_code=403)


@alert_api.route("/priority/batch/<priority>/", methods=["GET"])
@api_login()
def change_priority_by_batch(priority, **kwargs):
    """
    Apply priority to all alerts matching the given filters using a background process

    Variables:
    priority     =>  priority to apply

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    start     =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v3/alert/priority/batch/HIGH/?q=al_av:*

    Result example:
    {"status": "QUEUED"}
    """
    action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
    priority = priority.upper()

    user = kwargs['user']
    q = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not q and not fq:
        return make_api_response({"success": False,
                                  "event_id": None},
                                 err="You need to at least provide a query to filter the data", status_code=400)
    if not q:
        q = fq.pop(0)
    tc = request.args.get('tc', None)
    start = request.args.get('start', None)

    msg = {
        "user": user['uname'],
        "action": "batch_workflow",
        "query": q,
        "tc": tc,
        "start": start,
        "fq": fq,
        "priority": priority,
        "queue_priority": QUEUE_PRIORITY
    }

    action_queue.push(QUEUE_PRIORITY, msg)

    return make_api_response({"status": "QUEUED"})


@alert_api.route("/status/<alert_id>/<status>/", methods=["GET"])
@api_login(required_priv=['W'])
def change_status(alert_id, status, **kwargs):
    """
    Change the status of a given alert

    Variables:
    alert_id    => ID of the alert to change the status
    status      => New status for the alert

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/alert/status/1234567890/MALICIOUS/

    Result example:
    {"success": true,
     "event_id": 0}
    """
    user = kwargs['user']
    status = status.upper()

    alert = STORAGE.get_alert(alert_id)

    if not alert:
        return make_api_response({"success": False, "event_id": None},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response("", "You are not allowed to see this alert...", 403)

    if status != alert.get('status', None):
        alert['status'] = status
        STORAGE.save_alert(alert_id, alert)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Alert already has status %s" % status,
                                 status_code=403)


@alert_api.route("/status/batch/<status>/", methods=["GET"])
@api_login()
def change_status_by_batch(status, **kwargs):
    """
    Apply status to all alerts matching the given filters using a background process

    Variables:
    status     =>  Status to apply

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    start     =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v3/alert/status/batch/MALICIOUS/?q=al_av:*

    Result example:
    {"status": "QUEUED"}
    """
    action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
    status = status.upper()

    user = kwargs['user']
    q = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not q and not fq:
        return make_api_response({"success": False,
                                  "event_id": None},
                                 err="You need to at least provide a query to filter the data", status_code=400)
    if not q:
        q = fq.pop(0)
    tc = request.args.get('tc', None)
    start = request.args.get('start', None)

    msg = {
        "user": user['uname'],
        "action": "batch_workflow",
        "query": q,
        "tc": tc,
        "start": start,
        "fq": fq,
        "status": status,
        "queue_priority": QUEUE_PRIORITY
    }

    action_queue.push(QUEUE_PRIORITY, msg)

    return make_api_response({"status": "QUEUED"})


@alert_api.route("/ownership/<alert_id>/", methods=["GET"])
@api_login(required_priv=['W'])
def take_ownership(alert_id, **kwargs):
    """
    Take ownership of a given alert

    Variables:
    alert_id    => ID of the alert to send to take ownership

    Arguments:
    None

    Data Block:
    None

    API call example:
    /api/v3/alert/ownership/1234567890/

    Result example:
    {"success": true}
    """
    user = kwargs['user']

    alert = STORAGE.get_alert(alert_id)

    if not alert:
        return make_api_response({"success": False},
                                 err="Alert ID %s not found" % alert_id,
                                 status_code=404)

    if not Classification.is_accessible(user['classification'], alert['classification']):
        return make_api_response({"success": False}, "You are not allowed to see this alert...", 403)

    if alert.get('owner', None) is None:
        alert.update({"owner": user['uname']})
        STORAGE.save_alert(alert_id, alert)
        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err="Alert is already owned by %s" % alert['owner'],
                                 status_code=403)


@alert_api.route("/ownership/batch/", methods=["GET"])
@api_login()
def take_ownership_by_batch(**kwargs):
    """
    Take ownership of all alerts matching the given filters using a background process

    Variables:
    None

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    start     =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v3/alert/ownership/batch/?q=event_id:"helloworld"

    Result example:
    { "success": true }
    """
    action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)

    user = kwargs['user']
    q = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not q and not fq:
        return make_api_response({"success": False,
                                  "event_id": None},
                                 err="You need to at least provide a query to filter the data", status_code=400)
    if not q:
        q = fq.pop(0)
    tc = request.args.get('tc', None)
    start = request.args.get('start', None)

    msg = {
        "user": user['uname'],
        "action": "ownership",
        "query": q,
        "tc": tc,
        "start": start,
        "fq": fq,
        "queue_priority": QUEUE_PRIORITY
    }

    action_queue.push(QUEUE_PRIORITY, msg)

    return make_api_response({"status": "QUEUED"})


@alert_api.route("/related/", methods=["GET"])
@api_login()
def find_related_alert_ids(**kwargs):
    """
    Return the list of all IDs related to the currently selected query

    Variables:
    None

    Arguments:
    q         =>  Main query to filter the data [REQUIRED]
    tc        =>  Time constraint to apply to the search
    start     =>  Time at which to start the days constraint
    fq        =>  Filter query applied to the data

    Data Block:
    None

    API call example:
    /api/v3/alert/related/?q=event_id:1

    Result example:
    ["1"]
    """
    user = kwargs['user']
    q = request.args.get('q', None)
    fq = request.args.getlist('fq')
    if not q and not fq:
        return make_api_response({"success": False,
                                  "event_id": None},
                                 err="You need to at least provide a query to filter the data", status_code=400)
    if not q:
        q = fq.pop(0)
    tc = request.args.get('tc', None)
    stime = request.args.get('start', None)

    fq_list = []

    if tc is not None and tc != "":
        if stime is not None:
            fq_list.append("reporting_ts:[%s-%s TO %s]" % (stime, tc, stime))
        else:
            fq_list.append("reporting_ts:[NOW-%s TO NOW]" % tc)
    elif stime is not None and stime != "":
        fq_list.append("reporting_ts:[* TO %s]" % stime)

    if fq:
        if isinstance(fq, list):
            fq_list.extend(fq)
        elif fq != "":
            fq_list.append(fq)

    return make_api_response([x['event_id'] for x in
                              STORAGE.stream_search('alert', q, fq=fq_list, access_control=user['access_control'])])
