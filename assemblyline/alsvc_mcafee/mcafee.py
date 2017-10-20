""" McAfee AntiVirus Scanning Service.

    This service wraps a local linux McAfee Command Line AV Scanner.

    If was tested against:
        McAfee VirusScan Command Line for Linux64 Version: 6.0.4.564 (x64)
        
    It expects the AV scanner to be located in EXE_PATH and a current
    DAT set to be in DAT_DIRECTORY.
"""
import os
from ftplib import FTP

import subprocess

from assemblyline.common.exceptions import ConfigException
from assemblyline.al.common.result import Result, SCORE
from assemblyline.al.common.av_result import VirusHitTag, VirusHitSection
from assemblyline.al.service.base import BatchServiceBase, UpdaterType, UpdaterFrequency


class McAfee(BatchServiceBase):
    """ McAfee AV Scanning Service. """

    # McAfee has a high startup cost so we batch up files and scan
    # multiple at once.
    BATCH_SIZE = 75
    BATCH_TIMEOUTSECS = 5

    SERVICE_CATEGORY = "Antivirus"
    SERVICE_DEFAULT_CONFIG = {
        'EXE_PATH': '/opt/al/support/mcafee/uvscan',
        'DAT_DIRECTORY': '/opt/al/var/avdat/mcafee/',
        'UPDATER_OFFLINE_URL': None,
        'AUTO_UPDATE': False,
    }
    SERVICE_DESCRIPTION = "This services wraps McAfee command line scanner 'uvscan'."
    SERVICE_ENABLED = True
    SERVICE_REVISION = BatchServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 512

    SUPPORTS_SRBATCH = True

    def __init__(self, cfg=None):
        super(McAfee, self).__init__(cfg)
        self.exe_path = self.cfg['EXE_PATH']
        self.dat_directory = self.cfg['DAT_DIRECTORY']
        self._av_info = ''
        self.last_update = None

        self._validate_config_or_die()

    def _validate_config_or_die(self):
        if not os.path.exists(self.exe_path):
            raise ConfigException(
                'Invalid or missing EXE_PATH: %s' % self.exe_path)
        if not os.path.isdir(self.dat_directory):
            raise ConfigException(
                'Invalid or missing DAT_DIRECTORY: %s' % self.dat_directory)
        if not os.path.isdir(self.working_directory):
            raise ConfigException(
                'Working directory does not exist %s' % self.working_directory)

    def get_tool_version(self):
        return self._av_info

    def execute_batch(self, request_batch):
        self.log.info('Execute batch of size %d', len(request_batch.requests))

        request_batch.download()
        paths_to_scan = []
        for request in request_batch.requests:
            if request.successful and request.local_path:
                paths_to_scan.append(request.local_path)

        # Initially mark all as failed.
        for request in request_batch.requests:
            request.successful = True
            request.error_is_recoverable = True
            request.result = Result()
            # request.error_text = 'Did not find an entry for this file in the AV output'

        scanner = McAfeeScanner(self.exe_path, self.dat_directory, self.working_directory)  # pylint: disable=E0602
        scan_results = scanner.scan_files(paths_to_scan)
        if not scan_results:
            return

        for original_path, av_result in scan_results.results.iteritems():
            request = request_batch.find_by_local_path(original_path)
            if not request:
                self.log.error('Could not find request associated with path %s', original_path)
                continue

            request.task.report_service_context(self._av_info)

            result = Result()
            for embedded_file, (is_virus, detection_type, virus_name, _reserved) in av_result.iteritems():
                if not is_virus:
                    continue
                result.append_tag(VirusHitTag(virus_name))
                result.add_section(VirusHitSection(virus_name, SCORE.SURE, embedded_file, detection_type))
            request.result = result
            request.successful = True

            request_batch.delete_downloaded()

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global McAfeeScanner  # pylint: disable=W0602
        from al_services.alsvc_mcafee.mcafee_lib import McAfeeScanner  # pylint: disable=W0612

    def start(self):
        # Instantiate a scanner now so we can fail early if construction doesn't work.
        scanner = McAfeeScanner(self.exe_path, self.dat_directory,
                                self.working_directory)  # pylint: disable=E0602,W0612

        self._av_info = scanner.get_version_info()
        self.last_update = "avvdat-%s.zip" % self._av_info.split("Defs:")[1].split(" ")[0]
        self._register_update_callback(self.update_mcafee, blocking=True, utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.QUARTER_DAY)
        self._av_info = scanner.get_version_info()

    def update_mcafee(self, **kwargs):
        cfg = kwargs.get('cfg', {})
        auto_update = cfg.get('AUTO_UPDATE', False)
        transport_url = cfg.get('UPDATER_OFFLINE_URL', None)

        if auto_update:
            from al_services.alsvc_mcafee.mcafee_lib import McAfeeScanner  # pylint: disable=W0612

            # Cleanup update dir
            update_dir = "/tmp/mcafupd_dir"
            subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)
            subprocess.call("mkdir -p {update_dir}".format(update_dir=update_dir), shell=True)
            out_file = os.path.join(update_dir, "avvdat-latest.zip")
            latest_avvdat_fname = "avvdat-latest.zip"

            if transport_url:
                from assemblyline.al.core.filestore import FileStore

                # Download update
                filestore = FileStore(transport_url)
                filestore.download("avvdat-latest.zip", out_file)
            else:
                ftp = FTP('ftp.mcafee.com')
                ftp.login()
                ftp.cwd('commonupdater2/current/vscandat1000/dat/0000/')
                file_list = ftp.nlst()
                latest_avvdat_fname = 'avvdat-0.zip'
                for filename in file_list:
                    if '.zip' in filename:
                        if int(filename[7:-4]) > int(latest_avvdat_fname[7:-4]):
                            latest_avvdat_fname = filename

                if self.last_update == latest_avvdat_fname:
                    return

                with open(out_file, "wb") as outf:
                    ftp.retrbinary("RETR %s" % latest_avvdat_fname, outf.write)

            subprocess.call(['unzip', '-o', out_file, '-d', self.dat_directory])
            scanner = McAfeeScanner(self.exe_path, self.dat_directory, self.working_directory)
            scanner.decompress_avdefinitions()
            self.last_update = latest_avvdat_fname
            subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)
