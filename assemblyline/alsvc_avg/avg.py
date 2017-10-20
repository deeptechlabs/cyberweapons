import codecs
import os
import re
import subprocess
import time

from assemblyline.al.common.result import Result, SCORE, TAG_TYPE
from assemblyline.al.common.av_result import VirusHitSection, VirusHitTag
from assemblyline.al.service.base import ServiceBase, UpdaterType, UpdaterFrequency


class Avg(ServiceBase):
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_DEFAULT_CONFIG = {
        'AUTOUPDATE': True,
        'AVG_PATH': '/usr/bin/avgscan',
        'UPDATER_OFFLINE_URL': None
    }
    SERVICE_DESCRIPTION = "This services wraps AVG's linux command line scanner 'avgscan'"
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 256
    SERVICE_CATEGORY = "Antivirus"

    def __init__(self, cfg=None):
        super(Avg, self).__init__(cfg)
        self.avg_path = self.cfg.get('AVG_PATH')
        if not os.path.exists(self.avg_path):
            self.log.error("AVG not found at %s. Avg service will likely be non functional.", self.avg_path)
        self._av_info = ''
        self.last_update = None

    def _fetch_raw_version(self):
        proc = subprocess.Popen([self.avg_path, 'fakearg'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _err = proc.communicate()
        av_date = None
        av_version = None
        for line in out.splitlines():
            if "Virus database version" in line:
                av_version = line.split(': ')[1]
            elif "Virus database release date" in line:
                av_date = line.split(': ')[1].strip()
                dt = parse(av_date)  # pylint: disable=E0602
                av_date = dt.strftime("%Y%m%d")
            if av_version and av_date:
                break
        return av_date, av_version, out

    def execute(self, request):
        request.result = Result()
        request.set_service_context(self._av_info)
        filename = request.download()

        # Generate the temporary resulting filename which AVG is going to dump the results in
        out_file = os.path.join(self.working_directory, "scanning_results.txt")

        cmd = [self.avg_path, "-H", "-p", "-o", "-w", "-b", "-j", "-a", "--report=%s" % out_file, filename]
        devnull = open('/dev/null', 'wb')
        proc = subprocess.Popen(cmd, stdout=devnull, stderr=devnull, cwd=os.path.dirname(self.avg_path))
        proc.wait()

        try:
            # AVG does not support unicode file names, so any results it returns for these files will be filtered out
            out_file_handle = codecs.open(out_file, mode='rb', encoding="utf-8", errors="replace")
            output = out_file_handle.read()
            out_file_handle.close()

            # 2- Parse the output and fill in the result objects
            self.parse_results_seq(output, request.result, len(self.working_directory))

        except Exception, scan_exception:
            self.log.error("AVG scanning was not completed: %s" % str(scan_exception))
            raise

    def get_avg_version(self):
        program_version = "AVG (linux) 13.x.xxxx"
        av_date = None
        av_version = None
        output = None

        for _ in range(0, 5):
            (av_date, av_version, output) = self._fetch_raw_version()
            if av_date and av_version:
                break
            time.sleep(1)

        if not (av_date and av_version):
            self.log.error("Could not fetch AVG version after 5 attempts. avgd may not yet be running. "
                           "version and dat info may be missing: %s", output)

        proc = subprocess.Popen([self.avg_path, "-v"], stdout=subprocess.PIPE)
        o, _e = proc.communicate()
        for line in o.splitlines():
            if "scanner version" in line:
                program_version = 'AVG (linux) ' + line[28:]
        if not av_version:
            av_version = "(not found)"  # Base virus database version in case parse fails
        return "Engine: {} DAT: {} - {}".format(program_version, av_version, av_date)

    def get_tool_version(self):
        return self._av_info

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global parse  # pylint: disable=W0602
        from dateutil.parser import parse  # pylint: disable=W0612

    def start(self):
        self._register_update_callback(self.update_avg, utype=UpdaterType.BOX,
                                       freq=UpdaterFrequency.QUARTER_DAY)
        self._av_info = self.get_avg_version()

    # noinspection PyUnboundLocalVariable,PyUnusedLocal
    def parse_results_seq(self, result_content, file_res, base_offset):
        results_parse = True

        for line in result_content.splitlines()[7:]:
            # This is used to identify the end of the scan results
            if line.strip().startswith('-----') and line.strip().endswith('-------'):
                results_parse = False

            if results_parse:
                split_result = None

                if not line.strip():
                    continue

                # AVG provides it's results after the filename on the same line without any escape characters.
                if line.strip().endswith(" is OK."):
                    os1 = line.rindex(" is OK.")
                    split_result = (line[0:os1], "", "OK")
                elif line.strip().endswith(" clean."):
                    pos1 = line.rindex(" clean.")
                    split_result = (line[0:pos1], "", "OK")
                elif ' May be infected by unknown virus ' in line:
                    split_result = line.partition(' May be infected by ')
                elif ' Virus found ' in line:
                    split_result = line.partition(' Virus found ')
                elif ' Virus identified ' in line:
                    split_result = line.partition(' Virus identified ')
                elif ' Trojan horse ' in line:
                    split_result = line.partition(' Trojan horse ')
                elif ' Found ' in line:
                    split_result = line.partition(' Found ')
                elif ' Password-protected' in line:
                    split_result = line.partition(' Password-protected')
                elif ' Contains macros' in line:
                    split_result = line.partition(' Contains macros')
                elif ' Corrupted executable file' in line:
                    split_result = line.partition(' Corrupted executable file')
                elif ' Potentially harmful program' in line:
                    pos1 = line.rindex(' Potentially harmful program')
                    split_result = (line[0:pos1], "", line[pos1:])
                elif ' Runtime packed' in line:
                    pos1 = line.rindex(' Runtime packed')
                    split_result = (line[0:pos1], "", line[pos1:])
                elif ' The file is signed with a broken digital signature, issued by: ' in line:
                    split_result = line.partition(' The file is signed with a ')
                elif ' Adware ' in line:
                    split_result = line.partition(' Adware ')
                elif ' Archive bomb' in line:
                    split_result = line.partition(' Archive Bomb')
                elif ' Could be a potentially harmful program ' in line:
                    split_result = line.partition(' Could be a potentially harmful program ')
                elif 'file is signed by an untrusted certificate':
                    # TODO: Add this to the result output in a formatted way.
                    continue
                else:
                    self.log.error('Unable to parse line: %s' % line)
                    raise Exception('Unable to parse line: %s' % line)

                if split_result:
                    filename, virus_type, virus_name = split_result  # pylint: disable=W0633

                    # Cleanup results
                    filename = filename[base_offset:].strip()
                    virus_type = virus_type.strip()
                    virus_name = virus_name.strip()

                    # parse results
                    if virus_name == "OK":
                        continue  # Ignore "is OK" result here
                    else:
                        if not virus_name:
                            virus_name = virus_type

                    # Check for embedded
                    embedded_filename = None
                    if ":" in filename:
                        embedded_filename = filename[filename.index(":") + 1:]

                    res = VirusHitSection(virus_name, Avg.get_line_score(virus_type), embedded_filename)
                    file_res.append_tag(VirusHitTag(virus_name))

                    cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", virus_name)
                    if cve_found:
                        file_res.add_tag(TAG_TYPE.EXPLOIT_NAME,
                                         virus_name[cve_found.start():cve_found.end()],
                                         SCORE.MED,
                                         usage='IDENTIFICATION')
                        file_res.add_tag(TAG_TYPE.FILE_SUMMARY,
                                         virus_name[cve_found.start():cve_found.end()],
                                         SCORE.MED,
                                         usage='IDENTIFICATION')
                    file_res.add_result(res)

    @staticmethod
    def get_line_score(line):
        score = SCORE.SURE
        if line.strip().endswith('Contains macros'):
            score = SCORE.LOW
        elif line.strip().endswith('Password-protected'):
            score = SCORE.INFO
        elif line.strip().endswith('Corrupted executable file'):
            score = SCORE.INFO
        return score

    def update_avg(self, **kwargs):
        cfg = kwargs.get('cfg', {})
        auto_update = cfg.get('AUTOUPDATE', False)
        transport_url = cfg.get('UPDATER_OFFLINE_URL', None)
        if auto_update:
            if transport_url:
                # To do offline updating:
                #   Drop the iavi file inside of a cart container on an FTP, HTTP or SFTP server
                #   Always name the cart file avg_update.cart
                #   Set an UPDATER_OFFLINE_URL for your transport in the service config

                import json
                from assemblyline.al.core.filestore import FileStore

                # Cleanup update dir
                update_dir = "/tmp/avgupd_dir"
                subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)
                subprocess.call("mkdir -p {update_dir}".format(update_dir=update_dir), shell=True)

                # Download update
                filestore = FileStore(transport_url)
                filestore.download("avg_update.cart", "{update_dir}/avg_update.cart".format(update_dir=update_dir))

                # Validate update
                proc = subprocess.Popen("cart -s {update_dir}/avg_update.cart".format(update_dir=update_dir),
                                        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate()
                name = json.loads(stdout)['name']

                # If this is not the same update, update!
                if name != self.last_update:
                    subprocess.call("cd {update_dir} && cart -d -f avg_update.cart".format(update_dir=update_dir),
                                    shell=True)
                    ret = subprocess.call("sudo /usr/bin/avgupdate --source=folder "
                                          "--path={update_dir}".format(update_dir=update_dir), shell=True)
                    if ret not in [0, 2]:
                        self.log.warning("'avgupdate' command failed with status: %s" % ret)
                    else:
                        self.last_update = name
                subprocess.call("rm -rf {update_dir}".format(update_dir=update_dir), shell=True)
            else:
                # Online update mode
                ret = subprocess.call("sudo avgupdate", shell=True)
                if ret not in [0, 2]:
                    self.log.warning("'avgupdate' command failed with status: %s" % ret)
