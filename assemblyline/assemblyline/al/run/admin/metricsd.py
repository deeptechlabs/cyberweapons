#!/usr/bin/env python

import elasticsearch
import json
import logging
import sys
import copy

from apscheduler.scheduler import Scheduler
from collections import Counter
from assemblyline.common.isotime import now_as_iso
from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.queue import CommsQueue
from threading import Lock


def cleanup_metrics(input_dict):
    output_dict = {}
    for k, v in input_dict.iteritems():
        items = k.split(".")
        parent = output_dict
        for i in items:
            if i not in parent:
                if items.index(i) == (len(items) - 1):
                    # noinspection PyBroadException
                    try:
                        parent[i] = int(v)
                    except:  # pylint:disable=W0702
                        if v == "true":
                            parent[i] = True
                        elif v == "false":
                            parent[i] = False
                        else:
                            parent[i] = v

                    break
                else:
                    parent[i] = {}
            parent = parent[i]

    return output_dict


class MetricsServer(object):

    SRV_METRICS = ['svc.cache_hit', 'svc.cache_miss', 'svc.cache_skipped', 'svc.execute_start', 'svc.execute_done',
                   'svc.execute_fail_recov', 'svc.execute_fail_nonrecov', 'svc.job_scored', 'svc.job_not_scored']
    INGEST_METRICS = ['ingest.duplicates', 'ingest.bytes_ingested', 'ingest.submissions_ingested', 'ingest.error',
                      'ingest.timed_out', 'ingest.submissions_completed', 'ingest.files_completed',
                      'ingest.bytes_completed', 'ingest.skipped', 'ingest.whitelisted']
    DISPATCH_METRICS = ['dispatch.files_completed']
    ALERT_METRICS = ['alert.received', 'alert.err_no_submission', 'alert.heavy_ignored', 'alert.proto_http',
                     'alert.proto_smtp', 'alert.proto_other', 'alert.saved']

    METRIC_TYPES = {'alerter': ALERT_METRICS,
                    'ingester': INGEST_METRICS,
                    'dispatcher': DISPATCH_METRICS,
                    'service': SRV_METRICS}

    def __init__(self, metrics_channel_name, logger, elastic_ip_p, elastic_port_p):
        self.metrics_channel_name = metrics_channel_name
        self.elastic_ip = elastic_ip_p
        self.elastic_port = elastic_port_p
        self.scheduler = Scheduler()
        self.metrics_queue = None
        self.es = None
        self.log = logger
        self.METRIC_TYPES.update(forge.get_config().core.metricsd.extra_metrics)

        self.counters_lock = Lock()
        self.counters = {}

    def serve_forever(self):

        self.metrics_queue = CommsQueue(self.metrics_channel_name)
        self.es = elasticsearch.Elasticsearch([{'host': self.elastic_ip, 'port': self.elastic_port}])

        self.scheduler.add_interval_job(
            self._create_aggregated_metrics,
            seconds=60, kwargs={"my_logger": self.log})

        self.scheduler.start()

        while True:
            for msg in self.metrics_queue.listen():
                if not msg or msg.get('type', None) != 'message':
                    continue
                metrics = json.loads(msg['data'])
                metrics_name = metrics.pop('name', None)
                metrics_type = metrics.pop('type', None)
                metrics_host = metrics.pop('host', None)
                _ = metrics.pop('instance', None)
                if not metrics_name or not metrics_type or not metrics_host:
                    continue

                with self.counters_lock:
                    if (metrics_name, metrics_type, metrics_host) not in self.counters:
                        self.counters[(metrics_name, metrics_type, metrics_host)] = Counter(metrics)
                    else:
                        self.counters[(metrics_name, metrics_type, metrics_host)] += Counter(metrics)

    def _create_aggregated_metrics(self, my_logger):
        my_logger.info("Copying counters.")
        with self.counters_lock:
            counter_copy = copy.deepcopy(self.counters)
            self.counters = {}

        my_logger.info("Aggregating metrics.")
        timestamp = now_as_iso()
        for component, counts in counter_copy.iteritems():
            component_name, component_type, component_host = component
            output_metrics = {'name': component_name,
                              'type': component_type,
                              'host': component_host}
            if component_type in self.METRIC_TYPES:
                output_metrics.update({k: counts.get(k, 0) for k in self.METRIC_TYPES[component_type]})
            else:
                my_logger.info("Skipping unknown component type: {cpt}".format(cpt=component_type))
                continue
            output_metrics['timestamp'] = timestamp
            output_metrics = cleanup_metrics(output_metrics)

            my_logger.info(output_metrics)
            try:
                self.es.create("al_metrics-%s" % timestamp[:10].replace("-", "."), component_type, output_metrics)
            except Exception as e:
                my_logger.exception(e)

        my_logger.info("Metrics aggregated... Waiting for next run.")


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    config = forge.get_config()
    al_log.init_logging('metricsd')
    log = logging.getLogger('assemblyline.metricsd')

    elastic_ip = config.get('logging', {}).get('logserver', {}).get('node', None)
    elastic_port = config.get('logging', {}).get('logserver', {}).get('elastic', {}).get('port', 9200)

    if not elastic_ip or not elastic_port:
        log.error("Elasticsearch cluster not configured in the seed. There is no need to gather stats on this box.")
        sys.exit(1)

    mserver = MetricsServer('SsMetrics', log, elastic_ip, elastic_port)
    mserver.serve_forever()
