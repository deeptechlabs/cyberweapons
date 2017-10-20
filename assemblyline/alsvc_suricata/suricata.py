import json
import os
import shutil
import subprocess
import time
import uuid
import tempfile
import re

from retrying import retry
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TAG_USAGE
from assemblyline.al.service.base import ServiceBase, UpdaterFrequency, UpdaterType

suricatasc = None
dateparser = None


class Suricata(ServiceBase):
    SERVICE_ACCEPTS = 'network/tcpdump'
    SERVICE_CATEGORY = 'Networking'
    SERVICE_ENABLED = True
    SERVICE_STAGE = "CORE"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_TIMEOUT = 60
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 1024

    SERVICE_DEFAULT_CONFIG = {
        "SURICATA_BIN": "/usr/local/bin/suricata",
        "SURE_SCORE": "MALWARE TROJAN CURRENT_EVENTS CnC Checkin",
        "VHIGH_SCORE": "EXPLOIT SCAN Adware PUP",
        "RULES_URLS": ["http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"],
        "HOME_NET": "any"
    }

    def __init__(self, cfg=None):
        super(Suricata, self).__init__(cfg)
        self.suricata_socket = None
        self.suricata_sc = None
        self.suricata_process = None
        self.last_rule_update = None
        self.rules_urls = cfg.get("RULES_URLS", self.SERVICE_DEFAULT_CONFIG["RULES_URLS"])
        self.home_net = cfg.get("HOME_NET", self.SERVICE_DEFAULT_CONFIG["HOME_NET"])
        self.oinkmaster_update_file = '/etc/suricata/oinkmaster'
        self.run_dir = None

    # Update our local rules using Oinkmaster
    def update_suricata(self, **_):
        command = ["/usr/sbin/oinkmaster",  "-Q", "-o", "/etc/suricata/rules"]
        for rules_url in self.rules_urls:
            command.extend(["-u", rules_url])
        subprocess.call(command)
        subprocess.call(["touch", self.oinkmaster_update_file])

    # Use an external tool to strip frame headers
    def strip_frame_headers(self, filepath):
        new_filepath = os.path.join(os.path.dirname(filepath), "striped.pcap")
        command = ["/usr/local/bin/stripe", "-r", filepath, "-w", new_filepath]

        subprocess.call(command)

        return new_filepath

    def start(self):
        self.run_dir = tempfile.mkdtemp(dir="/tmp")
        self._register_update_callback(self.update_suricata, execute_now=True, utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.QUARTER_DAY)
        self.replace_suricata_config()
        self.start_suricata_if_necessary()

    # The rules are updated once per day, so each day we have a new tool version
    def get_tool_version(self):
        return os.path.getmtime(self.oinkmaster_update_file)

    # When we're shutting down, kill the Suricata child process as well
    def stop(self):
        self.kill_suricata()
        if self.run_dir is not None:
            if os.path.exists(self.run_dir):
                shutil.rmtree(self.run_dir)
            self.run_dir = None

    # Kill the process if it isn't ending
    def kill_suricata(self):
        if self.suricata_process:
            try:
                self.log.info("Trying to kill Suricata (%s)" % (str(self.suricata_process.pid)))
                self.suricata_process.kill()
            except Exception as e:
                self.log.exception("Failed to kill Suricata (%s): %s" % (str(self.suricata_process.pid), e.message))

    # Reapply our service configuration to the Suricata yaml configuration
    def replace_suricata_config(self):
        source_path = os.path.join(self.source_directory, 'conf', 'suricata.yaml')
        dest_path = os.path.join(self.run_dir, 'suricata.yaml')
        home_net = re.sub(r"([/\[\]])", r"\\\1", self.home_net)
        with open(source_path) as sp:
            with open(dest_path, "w") as dp:
                dp.write(sp.read().replace("__HOME_NET__", home_net))

    def reload_rules_if_necessary(self):
        if self.last_rule_update < self.get_tool_version():
            self.reload_rules()

    # Send the reload_rules command to the socket
    def reload_rules(self):
        ret = self.suricata_sc.send_command("reload-rules")

        if not ret and ret["return"] != "OK":
            self.log.exception("Failed to reload Suricata rules")

    def start_suricata_if_necessary(self):
        if not self.suricata_running():
            self.launch_suricata()

    # Try connecting to the Suricata socket
    def suricata_running(self):
        if self.suricata_sc is None:
            return False
        try:
            self.suricata_sc.connect()
        except suricatasc.SuricataException:
            return False
        return True

    # Retry with exponential backoff until we can actually connect to the Suricata socket
    @retry(retry_on_result=lambda x: x is False, wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_delay=120000)
    def suricata_running_retry(self):
        return self.suricata_running()

    # Launch Suricata using a UID socket
    def launch_suricata(self):
        self.suricata_socket = os.path.join(self.run_dir, str(uuid.uuid4()) + '.socket')

        command = [
            self.cfg.get('SURICATA_BIN'),
            "-c", os.path.join(self.run_dir, 'suricata.yaml'),
            "--unix-socket=%s" % self.suricata_socket,
            "--pidfile", "%s/suricata.pid" % self.run_dir,
        ]

        self.log.info('Launching Suricata: %s' % (' '.join(command)))

        self.suricata_process = subprocess.Popen(command)

        self.suricata_sc = suricatasc.SuricataSC(self.suricata_socket)

        # Schedule a job to delete the socket when it isn't needed any longer
        self._register_cleanup_op(
            {
                'type': 'shell',
                'args': ["rm", "-rf", self.run_dir]
            }
        )
        # Note, in case the process is terminated without calling stop()
        self._register_cleanup_op(
            {
                'type': 'shell',
                'args': ["pkill", "--SIGKILL", "--nslist", "pid", "--ns", str(self.suricata_process.pid), "-f",
                         self.cfg.get('SURICATA_BIN')]
            }
        )

        if not self.suricata_running_retry():
            raise Exception('Suricata could not be started.')
        self.last_rule_update = time.time()

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global suricatasc, dateparser
        import suricatasc
        import dateutil.parser as dateparser

    def execute(self, request):
        file_path = request.download()
        result = Result()

        # restart Suricata if we need to
        self.start_suricata_if_necessary()

        # Update our rules if they're stale,
        self.reload_rules_if_necessary()

        # Strip frame headers from the PCAP, since Suricata sometimes has trouble parsing strange PCAPs
        stripped_filepath = self.strip_frame_headers(file_path)

        # Pass the pcap file to Suricata via the socket
        ret = self.suricata_sc.send_command("pcap-file", {
            "filename": stripped_filepath,
            "output-dir": self.working_directory
        })

        if not ret or ret["return"] != "OK":
            self.log.exception("Failed to submit PCAP for processing: %s" % ret['message'])

        # Wait for the socket finish processing our PCAP
        while True:
            time.sleep(1)
            ret = self.suricata_sc.send_command("pcap-current")

            if ret and ret["message"] == "None":
                break

        alerts = {}
        signatures = {}
        domains = []
        ips = []
        urls = []

        # Parse the json results of the service
        for line in open(os.path.join(self.working_directory, 'eve.json')):
            record = json.loads(line)

            timestamp = dateparser.parse(record['timestamp']).isoformat(' ')
            src_ip = record['src_ip']
            src_port = record['src_port']
            dest_ip = record['dest_ip']
            dest_port = record['dest_port']

            if src_ip not in ips:
                ips.append(src_ip)
            if dest_ip not in ips:
                ips.append(dest_ip)

            if record['event_type'] == 'http':
                if 'hostname' not in record['http'] or 'url' not in record['http']:
                    continue

                domain = record['http']['hostname']
                if domain not in domains and domain not in ips:
                    domains.append(domain)
                url = "http://" + domain + record['http']['url']
                if url not in urls:
                    urls.append(url)

            if record['event_type'] == 'dns':
                if 'rrname' not in record['dns']:
                    continue
                domain = record['dns']['rrname']
                if domain not in domains and domain not in ips:
                    domains.append(domain)

            if record['event_type'] == 'alert':
                if 'signature_id' not in record['alert'] or 'signature' not in record['alert']:
                    continue
                signature_id = record['alert']['signature_id']
                signature = record['alert']['signature']

                if signature_id not in alerts:
                    alerts[signature_id] = []
                if signature_id not in signatures:
                    signatures[signature_id] = signature

                alerts[signature_id].append("%s %s:%s -> %s:%s" % (timestamp, src_ip, src_port, dest_ip, dest_port))

        # Create the result sections if there are any hits
        if len(alerts) > 0:
            for signature_id, signature in signatures.iteritems():
                score = SCORE.NULL
                tag_weight = TAG_WEIGHT.NULL

                if any(x in signature for x in self.cfg.get("SURE_SCORE").split()):
                    score = SCORE.SURE
                    tag_weight = TAG_WEIGHT.SURE

                if any(x in signature for x in self.cfg.get("VHIGH_SCORE").split()):
                    score = SCORE.VHIGH
                    tag_weight = TAG_WEIGHT.VHIGH

                section = ResultSection(score, '%s: %s' % (signature_id, signature))
                for flow in alerts[signature_id][:10]:
                    section.add_line(flow)
                if len(alerts[signature_id]) > 10:
                    section.add_line('And %s more flows' % (len(alerts[signature_id]) - 10))
                result.add_section(section)

                # Add a tag for the signature id and the message
                result.add_tag(TAG_TYPE.SURICATA_SIGNATURE_ID, str(signature_id), tag_weight,
                               usage=TAG_USAGE.IDENTIFICATION)
                result.add_tag(TAG_TYPE.SURICATA_SIGNATURE_MESSAGE, signature, tag_weight,
                               usage=TAG_USAGE.IDENTIFICATION)

            # Add tags for the domains, urls, and IPs we've discovered
            for domain in domains:
                result.add_tag(TAG_TYPE.NET_DOMAIN_NAME, domain, TAG_WEIGHT.VHIGH, usage=TAG_USAGE.CORRELATION)
            for url in urls:
                result.add_tag(TAG_TYPE.NET_FULL_URI, url, TAG_WEIGHT.VHIGH, usage=TAG_USAGE.CORRELATION)
            for ip in ips:
                result.add_tag(TAG_TYPE.NET_IP, ip, TAG_WEIGHT.VHIGH, usage=TAG_USAGE.CORRELATION)

            # Add the original Suricata output as a supplementary file in the result
            request.add_supplementary(os.path.join(self.working_directory, 'eve.json'), 'json', 'SuricataEventLog.json')

        # Add the stats.log to the result, which can be used to determine service success
        if os.path.exists(os.path.join(self.working_directory, 'stats.log')):
            request.add_supplementary(os.path.join(self.working_directory, 'stats.log'), 'log', 'stats.log')

        request.result = result
