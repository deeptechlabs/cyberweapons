import datetime
import os
import subprocess

from assemblyline.common.exceptions import ConfigException, RecoverableError
from assemblyline.al.common.result import Result, SCORE
from assemblyline.al.common.av_result import VirusHitTag, VirusHitSection
from assemblyline.al.service.base import BatchServiceBase, UpdaterType, UpdaterFrequency
from al_services.alsvc_bitdefender.bitdefender_lib import BitDefenderScanner


class BitDefender(BatchServiceBase):
    SERVICE_CATEGORY = 'Antivirus'
    SERVICE_ENABLED = True
    SERVICE_REVISION = BatchServiceBase.parse_revision('$Id$')
    SERVICE_DEFAULT_CONFIG = {
        'EXE_PATH': '/usr/bin/bdscan',
        'DAT_DIRECTORY': '/opt/al/var/avdat/bitdefender',
        'AUTOUPDATE': False,
        'UPDATER_OFFLINE_URL': None,
        'LICENCE_KEY': None
    }
    SERVICE_DESCRIPTION = "This services wraps BitDefender's linux command line scanner 'bdscan'"
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 512
    SUPPORTS_SRBATCH = True

    def __init__(self, cfg=None):
        super(BitDefender, self).__init__(cfg)
        self.exe_path = self.cfg.get('EXE_PATH', '')
        self._validate_config_or_die()
        self._av_info = ''

    def _validate_config_or_die(self):
        if not os.path.isfile(self.exe_path):
            raise ConfigException('Missing or invalid EXE_PATH: %s' % self.exe_path)

    def execute_batch(self, request_batch):
        # BitDefender scans a folder at a time. Download all inputs to a folder
        # and scan it.
        batch_folder = request_batch.download()

        # Initially mark all as failed. 
        for request in request_batch.requests:
            request.successful = True
            request.result = Result()
            request.error_is_recoverable = True
            request.error_text = 'Did not found an entry for this file in the AV output'

        scanner = BitDefenderScanner(self.working_directory, self.exe_path)

        try:
            scan_results = scanner.scan_folder(batch_folder)

            for original_path, av_result in scan_results.results.iteritems():
                request = request_batch.find_by_local_path(original_path)
                if not request:
                    self.log.error("Could not find task associated with path: %s\n.", original_path)
                    continue

                result = Result()
                for embedded_file, (is_virus, infection_type, infection_name, _) in av_result.iteritems():
                    if not is_virus:
                        continue

                    score = SCORE.HIGH
                    if infection_type == 'infected':
                        score = SCORE.SURE

                    result.append_tag(VirusHitTag(infection_name))
                    result.add_section(VirusHitSection(infection_name, score, embedded_file, infection_type))

                    # TODO(CVE / Exploit tag extraction)

                request.result = result
                request.successful = True
                request.task.report_service_context(self._av_info)
        except RecoverableError, rec_err:
            for request in request_batch.requests:
                request.successful = False
                request.error_text = rec_err.message
        finally:
            request_batch.delete_downloaded()

    def get_bd_version_info(self):
        p = subprocess.Popen([self.exe_path, '--info'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _err = p.communicate()

        product_version = 'unknown'
        dat_version = 'unknown'
        for line in out.splitlines():
            if " Unices " in line:
                product_version = line.split(" Unices ")[1]
            elif "Update time" in line:
                dat_version = datetime.datetime.strptime(
                    line.split(": ")[1], "%a %b %d %H:%M:%S %Y").strftime("%Y%m%d")
        return "Engine: {}  DAT: {}".format(product_version, dat_version)

    def get_tool_version(self):
        return self._av_info

    def start(self):
        self._register_update_callback(self.update_bitdefender, blocking=True, utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.QUARTER_DAY)
        BitDefenderScanner('/tmp', self.exe_path)
        self._av_info = self.get_bd_version_info()

    @staticmethod
    def update_bitdefender(**kwargs):
        cfg = kwargs.get('cfg', {})
        auto_update = cfg.get('AUTOUPDATE', False)
        transport_url = cfg.get('UPDATER_OFFLINE_URL', None)
        if auto_update:
            import os
            path = os.path.dirname(os.path.realpath(__file__))

            if transport_url:
                # To do offline updating:
                #   Drop the cumulative.zip file on an FTP, HTTP or SFTP server
                #   Set an UPDATER_OFFLINE_URL for your transport in the service config
                from assemblyline.al.core.filestore import FileStore

                # Cleanup update dir
                update_dir = "/tmp/bdupd_dir"
                subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)
                subprocess.call("mkdir -p {update_dir}".format(update_dir=update_dir), shell=True)

                # Download update
                filestore = FileStore(transport_url)
                filestore.download("cumulative.zip", "{update_dir}/cumulative.zip".format(update_dir=update_dir))

                subprocess.call(["sudo", os.path.join(path, "offline_updater.sh")])
                subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)

            else:
                # Online update
                subprocess.call(["sudo", os.path.join(path, "online_updater.sh")])
