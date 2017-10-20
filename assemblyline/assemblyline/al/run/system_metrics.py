#!/usr/bin/env python

import elasticsearch
import json
import logging
import psutil
import os
import sys
import urllib2

from apscheduler.scheduler import Scheduler

from assemblyline.common.net import get_hostname, get_hostip
from assemblyline.al.common import forge, log as al_log
from assemblyline.common.isotime import now_as_local, now_as_iso

config = forge.get_config(static_seed=os.getenv("AL_SEED_STATIC"))
al_log.init_logging('system_metrics')
log = logging.getLogger('assemblyline.system_metrics')

previous_net_io = None
previous_disk_io = None

SOLR_ADMIN_URL = '%s/admin/mbeans?stats=true&wt=json&cat=QUERYHANDLER&cat=CORE&key=/update&key=/select&key=searcher'
SOLR_CORE_URL = 'admin/cores?wt=json&indexInfo=false'
SOLR_URL_BUILDER = 'http://localhost:8093/internal_solr/%s'
RIAK_STATS_URL = 'http://localhost:8098/stats'


def calculate_system_metrics(es, cur_ip, cur_host):
    global previous_disk_io, previous_net_io
    log.info("Starting system metrics calculation...")

    # Calculate memory usage
    mem = psutil.phymem_usage()

    # Calculate disk usage
    disk_usage = {}
    disk_usage_agg = {
        'total': 0,
        'used': 0,
        'free': 0
    }
    disk_id = 0
    for part in psutil.disk_partitions():
        usage = psutil.disk_usage(part.mountpoint)
        disk_usage[disk_id] = {
            'total': usage.total,
            'used': usage.used,
            'free': usage.free,
            'device': part.device,
            'mountpoint': part.mountpoint
        }
        disk_usage_agg['total'] += usage.total
        disk_usage_agg['used'] += usage.used
        disk_usage_agg['free'] += usage.free

    # Calculate disk IO
    current_disk_io_counters = {
        'agg': {
            'read_bytes': 0,
            'write_bytes': 0
        }
    }
    for k, v in psutil.disk_io_counters(perdisk=True).iteritems():
        drive = k[:3]
        if drive not in current_disk_io_counters:
            current_disk_io_counters[drive] = {'read_bytes': v.read_bytes, 'write_bytes': v.write_bytes}
        else:
            current_disk_io_counters[drive]['read_bytes'] += v.read_bytes
            current_disk_io_counters[drive]['write_bytes'] += v.write_bytes

        current_disk_io_counters['agg']['read_bytes'] += v.read_bytes
        current_disk_io_counters['agg']['write_bytes'] += v.write_bytes

    if not previous_disk_io:
        disk_io_counters = {}
        for drive in current_disk_io_counters.keys():
            disk_io_counters[drive] = {
                'read_bytes': 0,
                'write_bytes': 0
            }
    else:
        disk_io_counters = {}
        for drive in current_disk_io_counters.keys():
            disk_io_counters[drive] = {k: v - previous_disk_io[drive][k]
                                       for k, v in current_disk_io_counters[drive].iteritems()}

    previous_disk_io = current_disk_io_counters

    # Calculate network IO
    current_net_io_counter = {}
    for k, v in psutil.net_io_counters(pernic=True).iteritems():
        if "vir" in k or "docker" in k or "br" in k or "bond" in k or "vnet" in k:
            continue

        if v.bytes_recv == 0 and v.bytes_sent:
            continue

        if k == 'lo':
            current_net_io_counter[k] = {
                'bytes_sent': v.bytes_sent,
                'bytes_recv': v.bytes_recv,
                'errin': v.errin,
                'errout': v.errout,
                'dropin': v.dropin,
                'dropout': v.dropout
            }
        else:
            if 'non_lo' in current_net_io_counter:
                current_net_io_counter['non_lo']['bytes_sent'] += v.bytes_sent
                current_net_io_counter['non_lo']['bytes_recv'] += v.bytes_recv
                current_net_io_counter['non_lo']['errin'] += v.errin
                current_net_io_counter['non_lo']['errout'] += v.errout
                current_net_io_counter['non_lo']['dropin'] += v.dropin
                current_net_io_counter['non_lo']['dropout'] += v.dropout
            else:
                current_net_io_counter['non_lo'] = {
                    'bytes_sent': v.bytes_sent,
                    'bytes_recv': v.bytes_recv,
                    'errin': v.errin,
                    'errout': v.errout,
                    'dropin': v.dropin,
                    'dropout': v.dropout
                }

    if not previous_net_io:
        net_io_counters = {}
        for net_type in ['non_lo', 'lo']:
            net_io_counters[net_type] = {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'errin': 0,
                'errout': 0,
                'dropin': 0,
                'dropout': 0
            }
    else:
        net_io_counters = {}
        for net_type in ['non_lo', 'lo']:
            net_io_counters[net_type] = {k: v - previous_net_io[net_type][k]
                                         for k, v in current_net_io_counter[net_type].iteritems()}

    previous_net_io = current_net_io_counter

    # Creates elasticsearch stats document
    stats = {
        "cpu": {
            "percent": psutil.cpu_percent()
        },
        "memory": {
            "total": mem.total,
            "free": mem.free,
            "used": mem.used,
            "cached": mem.cached
        },
        "disk_usage": disk_usage,
        "disk_usage_agg": disk_usage_agg,
        "net_io": net_io_counters,
        "disk_io": disk_io_counters,
        "load": os.getloadavg()[0],
        "timestamp": now_as_iso(),
        "host": cur_host,
        "ip": cur_ip
    }
    try:
        es.create("system_metrics-%s" % now_as_local()[:10].replace("-", "."), "metrics", stats)
    except Exception as e:
        log.exception(e)
    log.debug(json.dumps(stats))
    log.info("System metrics sent to elasticsearch... Waiting for next run.")


def is_riak(ip, host):
    nodes = config.get('datastore', {}).get('riak', {}).get('nodes', [])
    if ip in nodes:
        return True

    if host in nodes:
        return True

    return False


def http_json_get(url):
    """Connect to Solr stat page and and return XML object"""
    data = None
    try:
        f = urllib2.urlopen(url)
        data = json.loads(f.read())
    except urllib2.HTTPError as e:
        log.debug('solr_stats plugin: can\'t get info, HTTP error: ' + str(e.code))
    except urllib2.URLError as e:
        log.debug('solr_stats plugin: can\'t get info: ' + str(e.reason))
    return data


def get_cores():
    url = SOLR_URL_BUILDER % SOLR_CORE_URL
    cores = []

    data = http_json_get(url)
    if data:
        cores = data.get('status', {}).keys()

    return cores


def fetch_info(core):
    """Connect to Solr stat page and and return XML object"""
    url = SOLR_URL_BUILDER % (SOLR_ADMIN_URL % core)
    return http_json_get(url)


def calculate_solr_metrics(es, cur_ip, cur_host):
    log.info("Starting solr metrics gathering...")
    excluded = [
        'searcherName',
        'reader',
        'indexVersion',
        'openedAt',
        'registeredAt',
        'readerDir',
        'handlerStart',
        'caching'
    ]
    stats = {}
    cores = get_cores()
    for core in cores:
        info = fetch_info(core)
        if info:
            for item in info.get('solr-mbeans'):
                if isinstance(item, dict):
                    for k, v in item.iteritems():
                        k = k.replace("/", "")
                        stats[k] = {x: y for x, y in v['stats'].iteritems() if x not in excluded}

        stats['host'] = cur_host
        stats['ip'] = cur_ip
        stats['core'] = core
        stats['timestamp'] = now_as_iso()

        try:
            es.create("solr-%s" % now_as_local()[:10].replace("-", "."), "solr", stats)
        except Exception as e:
            log.exception(e)

    log.info("Solr metrics sent to elasticsearch... Waiting for next run.")


def calculate_riak_metrics(es, cur_ip, cur_host):
    log.info("Starting riak metrics gathering...")
    keep_list = [
        # vnode GETS
        "vnode_get_fsm_time_100",
        "vnode_get_fsm_time_95",
        "vnode_get_fsm_time_99",
        "vnode_get_fsm_time_mean",
        "vnode_gets",

        # vnode PUTs
        "vnode_put_fsm_time_100",
        "vnode_put_fsm_time_95",
        "vnode_put_fsm_time_99",
        "vnode_put_fsm_time_mean",
        "vnode_puts",

        # Search Index
        "search_index_fail_count",
        "search_index_fail_one",
        "search_index_latency_95",
        "search_index_latency_99",
        "search_index_latency_999",
        "search_index_latency_max",
        "search_index_latency_mean",
        "search_index_latency_min",
        "search_index_throughput_count",
        "search_index_throughput_one",

        # Search Queries
        "search_query_fail_count",
        "search_query_fail_one",
        "search_query_latency_95",
        "search_query_latency_99",
        "search_query_latency_999",
        "search_query_latency_max",
        "search_query_latency_mean",
        "search_query_latency_min",
        "search_query_throughput_count",
        "search_query_throughput_one",

        # Read repairs
        "read_repairs",
        "read_repairs_counter",
        "read_repairs_counter_total",

        # Protobuf connections
        "pbc_active",
        "pbc_connects",

        # Node PUTs
        "node_put_fsm_time_100",
        "node_put_fsm_time_95",
        "node_put_fsm_time_99",
        "node_put_fsm_time_mean",
        "node_puts",

        # Node GETs
        "node_get_fsm_time_100",
        "node_get_fsm_time_95",
        "node_get_fsm_time_99",
        "node_get_fsm_time_mean",
        "node_gets",

        # GET objsize
        "node_get_fsm_objsize_100",
        "node_get_fsm_objsize_95",
        "node_get_fsm_objsize_99",
        "node_get_fsm_objsize_mean",

    ]
    data = http_json_get(RIAK_STATS_URL)
    if data:
        stats = {k: v for k, v in data.iteritems() if k in keep_list}

        stats['host'] = cur_host
        stats['ip'] = cur_ip
        stats['timestamp'] = now_as_iso()

        try:
            es.create("riak-%s" % now_as_local()[:10].replace("-", "."), "riak", stats)
        except Exception as e:
            log.exception(e)

    log.info("Riak metrics sent to elasticsearch... Waiting for next run.")


def main():
    global previous_disk_io, previous_net_io
    elastic_ip = config.get('logging', {}).get('logserver', {}).get('node', None)
    elastic_port = config.get('logging', {}).get('logserver', {}).get('elastic', {}).get('port', 9200)

    if not elastic_ip or not elastic_port:
        log.error("Elasticsearch cluster not configured in the seed. There is no need to gather stats on this box.")
        sys.exit(1)

    scheduler = Scheduler()
    cur_host = get_hostname()
    cur_ip = get_hostip()
    es = elasticsearch.Elasticsearch([{'host': elastic_ip, 'port': elastic_port}])

    scheduler.add_interval_job(calculate_system_metrics, seconds=60,
                               kwargs={"es": es, "cur_ip": cur_ip, "cur_host": cur_host})

    if is_riak(cur_ip, cur_host):
        scheduler.add_interval_job(calculate_solr_metrics, seconds=60,
                                   kwargs={"es": es, "cur_ip": cur_ip, "cur_host": cur_host})

        scheduler.add_interval_job(calculate_riak_metrics, seconds=60,
                                   kwargs={"es": es, "cur_ip": cur_ip, "cur_host": cur_host})

    scheduler.daemonic = False
    scheduler.start()


if __name__ == "__main__":
    main()
