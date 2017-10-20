#!/usr/bin/env python
import time
import logging

from assemblyline.al.common import forge, log as al_log, queue
from assemblyline.al.core.datastore import SearchException
from assemblyline.common.charset import safe_str

ds = forge.get_datastore()

DATABASE_NUM = 4
config = forge.get_config()
al_log.init_logging('workflow_filter')
log = logging.getLogger('assemblyline.workflow_filter')
action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
QUEUE_PRIORITY = -1


def get_last_reporting_ts(p_start_ts):
    log.info("Finding reporting timestamp for the last alert since {start_ts}...".format(start_ts=p_start_ts))
    args = [('sort', 'reporting_ts desc'), ('rows', '1'), ('fl', 'reporting_ts')]
    result = ds.direct_search("alert", "reporting_ts:[{start_ts} TO *]".format(start_ts=p_start_ts), args=args)
    docs = result.get('response', {}).get('docs', [{}]) or [{}]
    ret_ts = docs[0].get("reporting_ts", p_start_ts)
    return ret_ts

# Do not alter alerts older then the beginning of the previous day.
start_ts = "NOW/DAY-1DAY"

while True:
    end_ts = get_last_reporting_ts(start_ts)
    if start_ts != end_ts:
        workflow_queries = [{
            'status': "TRIAGE",
            'name': "Triage all with no status",
            'created_by': "SYSTEM",
            'query': "NOT status:*"
        }]

        for item in ds.stream_search("workflow", "status:MALICIOUS"):
            workflow_queries.append(item)

        for item in ds.stream_search("workflow", "status:NON-MALICIOUS"):
            workflow_queries.append(item)

        for item in ds.stream_search("workflow", "status:ASSESS"):
            workflow_queries.append(item)

        for item in ds.stream_search("workflow", '-status:["" TO *]'):
            workflow_queries.append(item)

        for aq in workflow_queries:
            log.info('Executing workflow filter: {name}'.format(name=aq['name']))
            labels = aq.get('label', [])
            status = aq.get('status', None)
            priority = aq.get('priority', None)

            if not status and not labels and not priority:
                continue

            fq = ["reporting_ts:[{start_ts} TO {end_ts}]".format(start_ts=start_ts, end_ts=end_ts)]

            fq_items = []
            if labels:
                for label in labels:
                    fq_items.append("label:\"{label}\"".format(label=label))
            if priority:
                fq_items.append("priority:*")
            if status:
                fq_items.append("status:*")

            fq.append("NOT ({exclusion})".format(exclusion=" AND ".join(fq_items)))

            count = 0
            try:
                for item in ds.stream_search('alert', aq['query'], fq=fq):
                    count += 1
                    if status and item.get('status', status) != status and item.get('status', status) != "TRIAGE":
                        labels.append("CONFLICT.%s" % item['status'])
                    msg = {
                        "action": "workflow",
                        "label": labels,
                        "priority": priority,
                        "status": status,
                        "event_id": item['_yz_rk'],
                        "queue_priority": QUEUE_PRIORITY
                    }
                    action_queue.push(QUEUE_PRIORITY, msg)
            except SearchException:
                log.warning("Invalid query '{query}' in "
                            "workflow filter '{name}' by '{user}'".format(query=safe_str(aq.get('query', '')),
                                                                          name=aq.get('name', 'unknown'),
                                                                          user=aq.get('created_by', 'unknown')))
                continue

            if count:
                log.info("{count} Alert(s) were affected by this filter.".format(count=count))
                if 'id' in aq:
                    ds.increment_workflow_counter(aq['id'], count)

    else:
        log.info("Skipping all workflow filter since there where no alerts created in the specified time period.")

    time.sleep(30)
    start_ts = end_ts
