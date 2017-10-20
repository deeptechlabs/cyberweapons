from assemblyline.al.common.av_result import AvScanResult
from assemblyline.common.exceptions import ConfigException, RecoverableError

import logging
import os
import subprocess
import uuid

DEFAULT_EXE_PATH = r'/usr/bin/bdscan'


class BitDefenderScanner(object):
    def __init__(self, working_dir, exe_path=None):
        self._working_dir = working_dir
        self.exe_path = exe_path or DEFAULT_EXE_PATH
        self.log = logging.getLogger('assemblyline.svc.bitdefender.common')
        self.validate_config_or_raise()

    def scan_folder(self, folder):
        output_filename = os.path.join(self._working_dir, str(uuid.uuid4()) + "_results.log")
        cmd_args = [self.exe_path, '--action=ignore', folder, '--log=%s' % output_filename]
        p = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        exit_code = p.returncode
        if exit_code not in [0, 1]:
            output_exists = os.path.exists(output_filename)
            output = ''
            if output_exists:
                with open(output_filename, 'r') as f:
                    output = f.read()
            if exit_code == 254 and not output_exists:
                raise RecoverableError(
                    "254 with no output. VM is likely being shutdown. Transient error.\nStdOut:%s\nStdErr:%s" % (
                        stdout, stderr))
            else:
                self.log.warn(
                 'Bitdefender returned unexpected ExitCode:%s. OutputFileExists:%s.\nOutput:%s.\nStdErr:%s.\nResult:%s',
                 exit_code, output_exists, stdout, stderr, output)

        try:
            result = self._parse_result_file(output_filename)
        except:
            self.log.exception('While parsing bitdefender output. stdout: %s stderr:%s.\n cmdline: %s',
                               stdout, stderr, ' '.join(cmd_args))
            raise
        return result

    def _parse_result_file(self, output_filename):
        avresult = AvScanResult()
        with open(output_filename, 'r') as output:
            for line in output:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('//'):
                    # line is a comment
                    continue
                if line.startswith('Results:'):
                    # reached end of parseable results
                    break
                embedded_file = ''
                scanned_filename, scan_result = line.split('\t', 1)
                original_file = scanned_filename
                if '=>' in scanned_filename:
                    original_file, embedded_file = scanned_filename.split('=>', 1)

                try:
                    if scan_result.strip().startswith('password protected'):
                        # skip password protected files
                        continue

                    if scan_result.strip() == 'ok':
                        is_virus, detection_type, virus_name = (False, 'ok', 'ok')
                    else:
                        is_virus = True
                        detection_type, virus_name = scan_result.split(': ', 1)
                except ValueError:
                    self.log.warn('Skipping invalid line in bd result for %s: %s\n%s', scanned_filename, scan_result,
                                  output)
                    continue

                if not virus_name:
                    self.log.warn('Skipping no virus_name in result: %s', scan_result)
                    continue

                avresult.add_result(original_file, is_virus, virus_name, detection_type, embedded_file)

        return avresult

    def validate_config_or_raise(self):
        if not os.path.isfile(self.exe_path):
            raise ConfigException('BitDefender not found at %s', self.exe_path)


class BitDefenderScannerNoFile(BitDefenderScanner):
    def scan_folder(self, folder):
        cmd_args = [self.exe_path, '--action=ignore', folder]
        p = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        exit_code = p.returncode
        if exit_code not in [0, 1]:
            self.log.warn('Bitdefender returned unexpected ExitCode:%s\nOutput:%s.\nStdErr:%s.\n',
                          exit_code, stdout, stderr)

        try:
            result = self._parse_result(stdout)
        except:
            self.log.exception('While parsing bitdefender output. stdout: %s stderr:%s.\n cmdline: %s',
                               stdout, stderr, ' '.join(cmd_args))
            raise
        return result

    def _parse_result(self, output):
        avresult = AvScanResult()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('//'):
                # line is a comment
                continue
            if line.startswith('Results:'):
                # reached end of parseable results
                break
            embedded_file = ''
            if '  ' not in line:
                continue

            splits = line.split(' ', 1)
            if len(splits) != 2:
                print "bad split: " + line
                continue
            scanned_filename, scan_result = line.split('  ', 1)
            original_file = scanned_filename
            if '=>' in scanned_filename:
                original_file, embedded_file = scanned_filename.split('=>', 1)

            try:
                if scan_result.strip().startswith('password protected'):
                    # skip password protected files
                    continue

                if scan_result.strip() == 'ok':
                    is_virus, detection_type, virus_name = (False, 'ok', 'ok')
                else:
                    is_virus = True
                    detection_type, virus_name = scan_result.split(': ', 1)
            except ValueError:
                self.log.warn('Skipping invalid line in bd result: %s\nout:%s',
                              scan_result, output)
                continue

            if not virus_name:
                self.log.warn('Skipping no virus_name in result: %s', scan_result)
                continue

            avresult.add_result(original_file, is_virus, virus_name,
                                detection_type, embedded_file)
        return avresult


if __name__ == '__main__':
    import pprint

    scanner = BitDefenderScanner('/tmp')
    pprint.pprint(scanner.scan_folder('./bad'))
