#!/usr/bin/env python

import json
import os
import requests
import time
import urllib

# noinspection PyBroadException
try:
    # noinspection PyUnresolvedReferences
    requests.packages.urllib3.disable_warnings()
except:
    pass

elasticsearch_deb = 'elasticsearch-2.3.3.deb'
kibana_deb = 'kibana_4.5.1_amd64.deb'
logstash_deb = 'logstash_2.3.3-1_all.deb'
filebeat_deb = 'filebeat_1.2.3_amd64.deb'


def install(alsi):
    alsi.sudo_apt_install([
        'apache2-utils',
        'nginx',
    ])

    alsi.install_oracle_java8()

    alsi.pip_install('requests')
    alsi.sudo_apt_install('curl')

    setup_rsyslog(alsi)
    install_nginx(alsi)
    install_elasticsearch(alsi)
    install_kibana4(alsi)
    install_logstash(alsi)
    install_filebeat(alsi)
    tune_elasticsearch(alsi)


def install_filebeat(alsi):
    alsi.milestone("Installing filebeat")
    fb_remote = "logger/%s" % filebeat_deb
    local_filebeat_deb = '/tmp/%s' % filebeat_deb
    alsi.fetch_package(fb_remote, local_filebeat_deb)

    alsi.runcmd('sudo dpkg -i ' + local_filebeat_deb)
    alsi.sudo_install_file('assemblyline/al/install/etc/filebeat/filebeat.yml', '/etc/filebeat/filebeat.yml')

    alsi.runcmd('sudo service filebeat restart')
    alsi.runcmd('sudo update-rc.d filebeat defaults 95 10')


def install_logstash(alsi):
    alsi.milestone("Installing logstash")
    ls_remote = "logger/%s" % logstash_deb
    local_logstash_deb = '/tmp/%s' % logstash_deb

    alsi.fetch_package(ls_remote, local_logstash_deb)
    alsi.runcmd('sudo dpkg -i ' + local_logstash_deb)
    alsi.runcmd('sudo mkdir -p /etc/pki/tls/certs')
    alsi.runcmd('sudo mkdir -p /etc/pki/tls/private')
    cert_opts = [
        '-subj "/CN=localhost/"',
        '-x509',
        '-batch',
        '-nodes',
        '-days 365',
        '-newkey rsa:2048',
        '-keyout /etc/pki/tls/private/logstash.key',
        '-out /etc/pki/tls/certs/logstash.crt'
    ]
    alsi.runcmd('sudo openssl req ' + ' '.join(cert_opts), piped_stdio=False)
    alsi.sudo_install_file('assemblyline/al/install/etc/logstash/logstash.conf', '/etc/logstash/conf.d/logstash.conf')
    alsi.runcmd('sudo service logstash start')
    alsi.runcmd('sudo update-rc.d logstash defaults 95 10')


def install_kibana4(alsi):
    alsi.milestone("Installing Kibana")
    alsi.runcmd('sudo service kibana stop', raise_on_error=False)
    kibana_remote = "logger/%s" % kibana_deb
    local_kibana_deb = '/tmp/%s' % kibana_deb

    alsi.fetch_package(kibana_remote, local_kibana_deb)
    alsi.runcmd('sudo dpkg -i ' + local_kibana_deb)
    alsi.sudo_sed_inline('/opt/kibana/config/kibana.yml', [
        's/host: \"0.0.0.0\"/host: \"localhost\"/',
        's/.*server\.ssl\.cert:.*/server.ssl.cert: \/etc\/nginx\/ssl\/nginx.crt/',
        's/.*server\.ssl\.key:.*/server.ssl.key: \/etc\/nginx\/ssl\/nginx.key/'
    ])

    alsi.runcmd('sudo service kibana start')
    alsi.runcmd('sudo update-rc.d kibana defaults 95 10')

    alsi.info("Waiting for kibana index to be ready...")
    time.sleep(10)

    alsi.info("Creating index patterns")
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/audit-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/audit.json')
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/logs-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/logs.json')
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/riak-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/riak.json')
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/solr-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/solr.json')
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/al_metrics-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/al_metrics.json')
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/index-pattern/system_metrics-* '
                '-d @/opt/al/pkg/assemblyline/al/install/etc/kibana/system_metrics.json')

    alsi.info("Creating extra index patterns")
    extra_indices = alsi.config.get('logging', {}).get('logserver', {}).get('kibana', {}).get('extra_indices', [])
    for index in extra_indices:
        title = json.load(open(index, "rb"))['title']
        alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/'
                    'index-pattern/{title} -d @{index}'.format(title=urllib.quote(title), index=index))

    alsi.info("Editting default config")
    alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/config/4.5.1 '
                '-d \'{"defaultIndex":"logs-*","format:number:defaultPattern":"0,0.[00]",'
                '"format:bytes:defaultPattern":"0,0.[00]b","format:percent:defaultPattern":"0,0.[00]%"}\'')

    alsi.info("Loading default dashboard objects")
    dashboards = json.load(open("/opt/al/pkg/assemblyline/al/install/etc/kibana/objects/Dashboards.json", "rb"))
    for obj in dashboards:
        alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/%s/%s -d \'%s\'' % (obj["_type"],
                                                                                  urllib.quote(obj["_id"]),
                                                                                  json.dumps(obj['_source'])))

    alsi.info("Loading default search objects")
    searches = json.load(open("/opt/al/pkg/assemblyline/al/install/etc/kibana/objects/Searches.json", "rb"))
    for obj in searches:
        alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/%s/%s -d \'%s\'' % (obj["_type"],
                                                                                  urllib.quote(obj["_id"]),
                                                                                  json.dumps(obj['_source'])))

    alsi.info("Loading default visualization objects")
    visualizations = json.load(open("/opt/al/pkg/assemblyline/al/install/etc/kibana/objects/Visualizations.json", "rb"))
    for obj in visualizations:
        alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/%s/%s -d \'%s\'' % (obj["_type"],
                                                                                  urllib.quote(obj["_id"]),
                                                                                  json.dumps(obj['_source'])))

    alsi.info("Loading extra objects")
    extra_viz = alsi.config.get('logging', {}).get('logserver', {}).get('kibana', {}).get('extra_viz', [])
    for viz in extra_viz:
        objects = json.load(open(viz, "rb"))
        for obj in objects:
            alsi.runcmd('curl -XPUT http://localhost:9200/.kibana/%s/%s -d \'%s\'' % (obj["_type"],
                                                                                      urllib.quote(obj["_id"]),
                                                                                      json.dumps(obj['_source'])))


def install_nginx(alsi):
    alsi.milestone("Installing nginx")
    kibana_pw = alsi.config['logging']['logserver']['kibana']['password']
    alsi.runcmd("sudo htpasswd -bc /etc/nginx/htpasswd.users kibanaadmin '" + kibana_pw + "'")
    alsi.runcmd('sudo rm -f /etc/nginx/sites-enabled/default')
    alsi.sudo_install_file('assemblyline/al/install/etc/nginx/conf.d/kibana_https.conf',
                           '/etc/nginx/sites-available/kibana')
    alsi.sudo_sed_inline('/etc/nginx/sites-available/kibana', [
        's/___LOGGER_IP___/%s/' % alsi.get_hostname()
    ])
    alsi.runcmd('sudo ln -sf /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/kibana')
    if not os.path.exists('/etc/nginx/ssl'):
        alsi.runcmd('sudo mkdir -p /etc/nginx/ssl/')
        ssl_crt = alsi.config['logging']['logserver'].get('ssl', {}).get('crt', None)
        ssl_key = alsi.config['logging']['logserver'].get('ssl', {}).get('key', None)
        if ssl_crt and ssl_key:
            if not os.path.exists('/etc/nginx/ssl/nginx.crt'):
                alsi.runcmd('sudo cp %s /etc/nginx/ssl/nginx.crt' % os.path.join(alsi.alroot, 'pkg', ssl_crt))
            if not os.path.exists('/etc/nginx/ssl/nginx.key'):
                alsi.runcmd('sudo cp %s /etc/nginx/ssl/nginx.key' % os.path.join(alsi.alroot, 'pkg', ssl_key))
        else:
            alsi.runcmd(
                r'sudo openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout '
                r'/etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt',
                piped_stdio=False)
    alsi.runcmd('sudo service nginx restart')


def install_elasticsearch(alsi):
    alsi.milestone("Installing elastisearch")
    elastic_config = alsi.config.get('logging', {}).get('logserver', {}).get('elasticsearch', {})
    es_remote = "logger/%s" % elasticsearch_deb
    local_es_deb = '/tmp/%s' % elasticsearch_deb

    alsi.fetch_package(es_remote, local_es_deb)
    alsi.runcmd('sudo dpkg -i ' + local_es_deb)

    alsi.sudo_sed_inline('/etc/elasticsearch/elasticsearch.yml', [
        's/# network.host: 192.168.0.1/network.host: 0.0.0.0/',
    ], check_exist=False)

    alsi.sudo_sed_inline('/etc/default/elasticsearch', [
        's/#ES_HEAP_SIZE=2g/ES_HEAP_SIZE=%sg/' % elastic_config.get('heap_size', 2),
    ], check_exist=False)

    index_ttl = elastic_config.get('index_ttl', {})
    templates = {}
    for k, v in index_ttl.iteritems():
        templates[v] = templates.get(v, []) + [k]

    for k, v in templates.iteritems():
        alsi.sudo_install_file('assemblyline/al/install/etc/cron/al-cleanup-indexes',
                               '/etc/cron.daily/al-cleanup-indexes-%s' % k)
        alsi.sudo_sed_inline('/etc/cron.daily/al-cleanup-indexes-%s' % k, [
            's/__DAYS__/%s/' % k,
            's/__PATTERNS__/%s/' % "|".join(v)
        ], create_backup=False)

    alsi.runcmd('sudo service elasticsearch restart', raise_on_error=False)
    alsi.runcmd('sudo update-rc.d elasticsearch defaults 95 10')


# noinspection PyBroadException
def tune_elasticsearch(alsi):
    alsi.milestone("Tuning elastisearch threadpool")
    try:
        result = requests.put('http://127.0.0.1:9200/_cluster/settings',
                              json.dumps({'persistent': {'threadpool.search.queue_size': 10000}}))
        if not result.ok:
            raise Exception("First ES REST call failed.")
    except:
        alsi.warn('ES REST API failed on first attempt. Trying again in 10 seconds.')
        time.sleep(10)
        result = requests.put('http://127.0.0.1:9200/_cluster/settings',
                              json.dumps({'persistent': {'threadpool.search.queue_size': 10000}}))
        if not result.ok:
            raise Exception("Final ES REST call failed. Aborting. \n:%s", result.text)


def setup_rsyslog(alsi):
    alsi.milestone("Setting up rsyslog to aggregate the logs")
    alsi.sudo_install_file(
        'assemblyline/al/install/etc/rsyslog.d/49-al.conf',
        '/etc/rsyslog.d/49-al.conf')

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/logrotate.d/al',
        '/etc/logrotate.d/al')
    alsi.runcmd('sudo chmod 644 /etc/logrotate.d/al')
    alsi.runcmd('sudo restart rsyslog')


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller

    installer = SiteInstaller()
    install(installer)
