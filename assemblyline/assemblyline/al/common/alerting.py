import hashlib
import time

from assemblyline.common.caching import TimeExpiredCache
from assemblyline.common.isotime import now_as_iso
from assemblyline.al.common import message
from assemblyline.al.common.queue import CommsQueue

DATABASE_NUM = 4

action_queue = None
Classification = None
Notice = None
summary_tags = (
    "AV_VIRUS_NAME", "EXPLOIT_NAME",
    "FILE_CONFIG", "FILE_OBFUSCATION", "FILE_SUMMARY",
    "IMPLANT_FAMILY", "IMPLANT_NAME", "NET_DOMAIN_NAME", "NET_IP",
    "TECHNIQUE_OBFUSCATION", "THREAT_ACTOR",
)
CACHE_LEN = 60 * 60 * 24
CACHE_EXPIRY_RATE = 60
cache = TimeExpiredCache(CACHE_LEN, CACHE_EXPIRY_RATE)
EXTENDED_SCAN_QUEUE_PRIORITY = 0


def alert_action(msg):
    global action_queue  # pylint: disable=W0603
    if not action_queue:
        from assemblyline.al.common import queue
        action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
    action_queue.push(EXTENDED_SCAN_QUEUE_PRIORITY, msg)


def get_submission_record(counter, datastore, sid):
    srecord = datastore.get_submission(sid)

    if not srecord:
        counter.increment('alert.err_no_submission')
        time.sleep(1.0)
        raise Exception("Couldn't find submission: %s" % sid)

    if srecord.get('state', 'unknown') != 'completed':
        time.sleep(1.0)
        raise Exception("Submission not finalized: %s" % sid)

    return srecord


def get_summary(datastore, srecord):
    global Classification
    if Classification is None:
        from assemblyline.al.common import forge
        Classification = forge.get_classification()

    max_classification = srecord['classification']

    summary = {
        'AV_VIRUS_NAME': set(),
        'EXPLOIT_NAME': set(),
        'FILE_ATTRIBUTION': set(),
        'FILE_CONFIG': set(),
        'FILE_OBFUSCATION': set(),
        'FILE_SUMMARY': set(),
        'FILE_YARA_RULE': set(),
        'IMPLANT_FAMILY': set(),
        'IMPLANT_NAME': set(),
        'NET_DOMAIN_NAME_S': set(),
        'NET_DOMAIN_NAME_D': set(),
        'NET_IP_S': set(),
        'NET_IP_D': set(),
        'TECHNIQUE_CONFIG': set(),
        'TECHNIQUE_OBFUSCATION': set(),
        'THREAT_ACTOR': set(),
    }

    for t in datastore.get_tag_list_from_keys(srecord.get('results', [])):
        tag_value = t['value']
        if tag_value == '':
            continue

        tag_context = t.get('context', None)
        tag_type = t['type']
        if tag_type in ('NET_DOMAIN_NAME', 'NET_IP'):
            if tag_context is None:
                tag_type += '_S'
            else:
                tag_type += '_D'
        elif tag_type not in summary:
            continue

        max_classification = Classification.max_classification(
            t['classification'], max_classification
        )

        sub_tag = {
            'EXPLOIT_NAME': 'EXP',
            'FILE_CONFIG': 'CFG',
            'FILE_OBFUSCATION': 'OB',
            'IMPLANT_FAMILY': 'IMP',
            'IMPLANT_NAME': 'IMP',
            'TECHNIQUE_CONFIG': 'CFG',
            'TECHNIQUE_OBFUSCATION': 'OB',
            'THREAT_ACTOR': 'TA',
        }.get(tag_type, None)
        if sub_tag:
            tag_type = 'FILE_ATTRIBUTION'
            tag_value = "%s [%s]" % (tag_value, sub_tag)

        if tag_type == 'AV_VIRUS_NAME':
            if tag_value in (
                'Corrupted executable file',
                'Encrypted container deleted',
                'Encrypted container deleted;',
                'Password-protected',
                'Malformed container violation',
            ):
                tag_type = 'FILE_SUMMARY'

            else: 
                av_name = (tag_context or '').split('scanner:')
                if len(av_name) == 2:
                    av_name = av_name[1]
                else:
                    av_name = datastore.service_name_from_key(t['key'])

                if av_name:
                    tag_value = "[%s] %s" % (av_name, tag_value)

        summary_values = summary.get(tag_type, None)
        if summary_values is not None:
            summary_values.add(tag_value)

    return max_classification, summary


def init_notice(raw, logger):
    global Notice  # pylint: disable=W0603
    if Notice is None:
        from assemblyline.al.common.notice import Notice

    logger.info('Sending alert: %s', str(raw))

    return Notice(raw)


def init_alert_parts(notice, extra_fields=None, extra_key_data=None):
    if extra_fields is None:
        extra_fields = []
    if extra_key_data is None:
        extra_key_data = []

    psid = notice.get('psid', "")
    sid = notice.get('sid')
    fields = extra_fields + ['filename', 'sid', 'al_score', 'ts', 'type']
    key_data = extra_key_data + [psid or sid, notice.get('ts', '')]

    return psid, sid, fields, key_data


# noinspection PyBroadException
def parse_submission_record(counter, datastore, sid, psid, logger):
    srecord = get_submission_record(counter, datastore, sid)
    root_req_file = datastore.get_file(srecord['files'][0][1])

    max_classification, summary = get_summary(datastore, srecord)
    summary_list = list(summary['FILE_SUMMARY'])

    extended_scan = 'unknown'
    if not psid:
        extended_scan = 'submitted' if psid is None else 'skipped'
    else:
        try:
            # Get errors from parent submission and submission. Strip keys
            # to only sha256 and service name. If there are any keys that
            # did not exist in the parent the extended scan is 'incomplete'.
            ps = datastore.get_submission(psid) or {}
            pe = set((x[:x.rfind('.')] for x in ps.get('errors', [])))
            e = set((x[:x.rfind('.')] for x in srecord.get('errors', [])))
            ne = e.difference(pe)
            extended_scan = 'incomplete' if ne else 'completed'
        except:  # pylint: disable=W0702
            logger.exception('Problem determining extended scan state:')

    domains = summary['NET_DOMAIN_NAME_D'].union(summary['NET_DOMAIN_NAME_S'])
    ips = summary['NET_IP_D'].union(summary['NET_IP_S'])

    return {
        'root_req_file': root_req_file,
        'summary_list': summary_list,
        'extended_scan': extended_scan,
        'domains': domains,
        'ips': ips,
        'summary': summary,
        'srecord': srecord,
        'max_classification': max_classification
    }


def save_alert(psid, alert, datastore, counter, event_id):
    if psid:
        alert_action({'action': 'update', 'alert': alert})
        counter.increment('alert.updated')
    else:
        datastore.save_alert(event_id, alert)
        counter.increment('alert.saved')

    msg = message.Message(to="*", sender='alerter', mtype=message.MT_ALERT_CREATED, body=alert)
    CommsQueue('alerts').publish(msg.as_dict())


def get_alert_update_parts(counter, datastore, event_id, sid, psid, logger):
    global cache
    # Check cache
    alert_update_p1, alert_update_p2 = cache.get(sid, (None, None))
    if alert_update_p1 is None or alert_update_p2 is None:
        parsed_record = parse_submission_record(counter, datastore, sid, psid, logger)
        alert_update_p1 = {
            'extended_scan': parsed_record['extended_scan'],
            'al_attrib': list(parsed_record['summary']['FILE_ATTRIBUTION']),
            'al_av': list(parsed_record['summary']['AV_VIRUS_NAME']),
            'al_domain': list(parsed_record['domains']),
            'al_domain_dynamic': list(parsed_record['summary']['NET_DOMAIN_NAME_D']),
            'al_domain_static': list(parsed_record['summary']['NET_DOMAIN_NAME_S']),
            'al_ip': list(parsed_record['ips']),
            'al_ip_dynamic': list(parsed_record['summary']['NET_IP_D']),
            'al_ip_static': list(parsed_record['summary']['NET_IP_S']),
            'al_request_end_time': parsed_record['srecord']['times']['completed'],
            'summary': parsed_record['summary_list'],
            'yara': list(parsed_record['summary']['FILE_YARA_RULE']),
        }
        alert_update_p2 = {
            'classification': parsed_record['max_classification'],
            'md5': parsed_record['root_req_file']['md5'],
            'sha1': parsed_record['root_req_file']['sha1'],
            'sha256': parsed_record['root_req_file']['sha256'],
            'size': parsed_record['root_req_file']['size'],
        }
        cache.add(sid, (alert_update_p1, alert_update_p2))

    alert_update_p1['event_id'] = event_id
    alert_update_p1['reporting_ts'] = now_as_iso()
    alert_update_p1['filename'] = 'unknown'

    return alert_update_p1, alert_update_p2


def create_alert(counter, datastore, logger, raw):
    """
    This is the default create alert function. If the generic alerts are not sufficient
    in your deployment, you can create another method like this one that would follow
    the same structure but with added parts where the comment blocks are located.
    """

    ###############################
    # Additional init goes here
    ###############################

    notice = init_notice(raw, logger)

    ###############################
    # Notice validation goes here
    ###############################

    alert = {}
    psid, sid, fields, key_data = init_alert_parts(notice)

    # We don't know what type of metadata will be sent to us, therefore we will add it all...
    fields += raw.get('metadata', {}).keys()

    ###############################
    # Additional notice parsing
    # and alert updating goes here
    ###############################

    # Generate alert event_id from key_data
    event_id = hashlib.md5(str(key_data)).hexdigest()

    # Get update parts
    alert_update_p1, alert_update_p2 = get_alert_update_parts(counter, datastore, event_id, sid, psid, logger)

    # Update alert with default values
    alert.update(alert_update_p1)

    # Update alert with notice.
    alert = notice.update_alert(fields, alert)

    # Update alert with computed values
    alert.update(alert_update_p2)

    save_alert(psid, alert, datastore, counter, event_id)
