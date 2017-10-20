#!/usr/bin/env python
import logging
import time

from threading import Thread

from assemblyline.al.common import forge, log as al_log, queue
from al_ui.helper.user import add_access_control

config = forge.get_config()
al_log.init_logging('alert_actions')
log = logging.getLogger('assemblyline.alert_actions')

DATABASE_NUM = 4
DEFAULT_QUEUE_PRIORITY = -2
EXTENDED_SCAN_QUEUE_PRIORITY = 0
TASKER_COUNT = config.core.alert_actions.tasker_count
WORKER_COUNT = config.core.alert_actions.worker_count


def determine_worker_id(event_id):
    return int(event_id, 16) % WORKER_COUNT


class AlertAction(object):
    def __init__(self):
        self.worker_threads = {
            x: Thread(target=run_worker_thread, args=(x,), name="worker-%s" % x) for x in range(WORKER_COUNT)
        }
        self.tasker_threads = {
            x: Thread(target=run_tasker_thread, args=(x,), name="tasker-%s" % x) for x in range(TASKER_COUNT)
        }

    def run(self):
        # Start worker threads
        for x in self.worker_threads:
            self.worker_threads[x].start()

        # Start tasker threads
        for x in self.tasker_threads:
            self.tasker_threads[x].start()

        # Wait for worker threads to finish
        for x in self.worker_threads:
            self.worker_threads[x].join()

        # Wait for tasker threads to finish
        for x in self.tasker_threads:
            self.tasker_threads[x].join()


class AlertActionWorker(object):
    def __init__(self, worker_id_p):
        self.action_queue = queue.PriorityQueue('alert-actions-worker-%s' % worker_id_p, db=DATABASE_NUM)
        self.datastore = forge.get_datastore()
        self.worker_id = worker_id_p

    def run(self):
        log.info("Starting alert_actions worker thread %s" % self.worker_id)
        while True:
            msgs = self.action_queue.pop(num=1)
            for msg in msgs:
                # noinspection PyBroadException
                try:
                    action = msg.get("action", "unknown")
                    if action == "workflow":
                        self._execute_workflow_action(msg['search_item'], msg['original_msg'])
                    elif action == "ownership":
                        self._execute_ownership_action(msg['search_item'], msg['user'])
                    elif action == "update":
                        self._execute_update_action(msg['original_msg'])
                    else:
                        log.warning("Unknown action '%s'. Skipping..." % action)

                except Exception:  # pylint: disable=W0702
                    log.exception("Exception occured while processing message: %s", str(msg))
            if not msgs:
                time.sleep(0.1)

    # noinspection PyBroadException
    def _execute_ownership_action(self, search_item, user):
        try:
            alert = self.datastore.get_alert(search_item['event_id'])
            if alert.get('owner', None) is None:
                alert.update({"owner": user['uname']})
                self.datastore.save_alert(alert['event_id'], alert)
                log.info("Alert %s now owned by %s.", alert['event_id'], alert['owner'])
            else:
                log.warning("Alert %s already owned by %s.", alert['event_id'], alert['owner'])
        except Exception:  # pylint: disable=W0702
            log.exception("Exception occured while trying take ownership of alert %s.", search_item['event_id'])

    def _execute_update_action(self, msg):
        nalert = msg.get('alert')
        event_id = str(nalert.get('event_id'))

        alert = self.datastore.get_alert(event_id) or {}

        # Merge fields...
        merged = {
            x: list(set(alert.get(x, [])).union(set(nalert.get(x, []))))
            for x in [
                'al_attrib', 'al_av', 'al_domain', 'al_ip', 'summary', 'yara',
                'al_domain_dynamic', 'al_domain_static', 'al_ip_dynamic',
                'al_ip_static'
            ]
        }

        # Sanity check.
        if not all([alert.get(x, None) == nalert.get(x, None) for x in config.core.alerter.constant_alert_fields]):
            Exception("Constant alert field changed. (%s, %s)" % (str(alert), str(nalert)))

        alert.update(nalert)
        alert.update(merged)

        self.datastore.save_alert(event_id, alert)

    # noinspection PyBroadException
    def _execute_workflow_action(self, search_item, message):
        try:
            alert = self.datastore.get_alert(search_item['event_id'])

            status = message.get('status', None)
            priority = message.get('priority', None)
            labels = set(message.get('label', []) or [])

            cur_label = set(alert.get('label', []))
            if (labels and labels.difference(labels.intersection(cur_label))) or \
                    (status and alert.get('status', None) != status) or \
                    (priority and alert.get('priority', None) != priority):

                out_msgs = []

                if status and alert.get('status', None) != status:
                    alert['status'] = status
                    out_msgs.append("changed status to {status}".format(status=status))

                if priority and alert.get('priority', None) != priority:
                    alert['priority'] = priority
                    out_msgs.append("changed priority to {priority}".format(priority=priority))

                if labels and labels.difference(labels.intersection(cur_label)):
                    cur_label = cur_label.union(labels)
                    alert['label'] = list(cur_label)
                    out_msgs.append("was added labels {label}".format(label=", ".join(labels)))

                self.datastore.save_alert(search_item['event_id'], alert)
                log.info("Alert {id} {out_msg}.".format(out_msg=", ".join(out_msgs), id=search_item['event_id']))
            else:
                log.info("Alert {id} already had all proper "
                         "workflow settings. Skipping...".format(id=search_item['event_id']))

        except Exception:  # pylint: disable=W0702
            log.exception("Exception occured while trying take workflow action on alert %s.", search_item['event_id'])


class AlertActionTasker(object):
    def __init__(self, tasker_id_p):
        self.action_queue = queue.PriorityQueue('alert-actions', db=DATABASE_NUM)
        self.worker_queues_map = {
            x: queue.PriorityQueue('alert-actions-worker-%s' % x, db=DATABASE_NUM) for x in range(WORKER_COUNT)
        }
        self.datastore = forge.get_datastore()
        self.tasker_id = tasker_id_p

    def run(self):
        log.info("Starting alert_actions tasker thread %s" % self.tasker_id)

        while True:
            msgs = self.action_queue.pop(num=1)
            for msg in msgs:
                if not self.valid_msg(msg):
                    continue
                action = msg.get("action", "unknown")
                log.info("New action received: %s [%s]" % (action, self.tasker_id))
                # noinspection PyBroadException
                try:
                    {
                        "workflow": self.process_workflow_action,
                        "batch_workflow": self.process_batch_workflow_action,
                        "ownership": self.process_ownership_action,
                        "unknown": self.process_unknown_action,
                        "update": self.process_update_action,
                    }[action](msg)
                except Exception:  # pylint: disable=W0702
                    log.exception("Exception occured while processing message: %s", str(msg))
            if not msgs:
                time.sleep(0.1)

    @staticmethod
    def valid_msg(msg):
        action = msg.get('action', None)
        if not action:
            log.warning("Invalid message: %s", str(msg))
            return False

        if action == 'update' and 'alert' in msg:
            return True

        if action == 'workflow':
            if 'priority' in msg or 'label' in msg or 'status' in msg:
                return True

        if 'user' in msg and 'query' in msg:
            return True

        log.warning("Invalid message: %s", str(msg))
        return False

    def prep_search(self, message):
        fq_list = []
        tc = message.get('tc', None)
        fq = message.get('fq', None)
        stime = message.get('start', None)

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

        user = self.datastore.get_user(message['user'])

        add_access_control(user)

        return "alert", message['query'], fq_list, user

    def process_ownership_action(self, message):
        bucket, query, fq, user = self.prep_search(message)
        queue_priority = message.pop("queue_priority", DEFAULT_QUEUE_PRIORITY)

        count = 0
        for item in self.datastore.stream_search(bucket, query, fq=fq, access_control=user['access_control']):
            event_id = item.get('event_id', None)
            if event_id:
                if queue_priority <= DEFAULT_QUEUE_PRIORITY:
                    count += 1
                    if count % 100 == 0:
                        queue_priority -= 1

                self.worker_queues_map[determine_worker_id(event_id)].push(queue_priority,
                                                                           {"action": "ownership",
                                                                            "search_item": item,
                                                                            "user": user})
            else:
                log.error("Could not find the alert's event_id so we could not "
                          "dispatch it to the proper worker. [%s]" % str(item))

    @staticmethod
    def process_unknown_action(msg):
        log.warning("Unknown message: %s", str(msg))

    def process_update_action(self, msg):
        event_id = msg.get('alert', {}).get('event_id', None)
        if event_id:
            self.worker_queues_map[determine_worker_id(event_id)].push(EXTENDED_SCAN_QUEUE_PRIORITY,
                                                                       {"action": "update",
                                                                        "original_msg": msg})
        else:
            log.error("Could not find the alert's event_id so we could not "
                      "dispatch it to the proper worker. [%s]" % str(msg))

    def process_workflow_action(self, message):
        event_id = message.get('event_id', None)
        queue_priority = message.pop("queue_priority", DEFAULT_QUEUE_PRIORITY)
        if event_id:
            self.worker_queues_map[determine_worker_id(event_id)].push(queue_priority,
                                                                       {"action": "workflow",
                                                                        "search_item": message,
                                                                        "original_msg": message})
        else:
            log.error("Could not find the alert's event_id so we could not "
                      "dispatch it to the proper worker. [%s]" % str(message))

    def process_batch_workflow_action(self, message):
        bucket, query, fq, user = self.prep_search(message)
        queue_priority = message.pop("queue_priority", DEFAULT_QUEUE_PRIORITY)

        count = 0
        for item in self.datastore.stream_search(bucket, query, fq=fq, access_control=user['access_control']):
            event_id = item.get('event_id', None)
            if event_id:
                if queue_priority <= DEFAULT_QUEUE_PRIORITY:
                    count += 1
                    if count % 100 == 0:
                        queue_priority -= 1

                self.worker_queues_map[determine_worker_id(event_id)].push(queue_priority,
                                                                           {"action": "workflow",
                                                                            "search_item": item,
                                                                            "original_msg": message})
            else:
                log.error("Could not find the alert's event_id so we could not "
                          "dispatch it to the proper worker. [%s]" % str(item))


def run_worker_thread(worker_id):
    AlertActionWorker(worker_id).run()


def run_tasker_thread(tasker_id):
    AlertActionTasker(tasker_id).run()


if __name__ == '__main__':
    log.info("AL Alert actions starting...")
    AlertAction().run()
