""" SysInternals SigCheck Service

This service uses the sigcheck application from sysinternals to determine if a
file is signed and if it was modified (post signature).  It also looks for
certificate authorities that are not the usual ones.  This is a filtering
service but it will also report if there is something suspicious related
with the signature/certificate.

"""

import os
import subprocess

from itertools import chain
from textwrap import dedent

from assemblyline.common.exceptions import ConfigException
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.service.base import ServiceBase

class SigCheck(ServiceBase):
    """SigCheck service. """
    AL_SigCheck_001 = Heuristic(
        "AL_SigCheck_001", "Invalid Signature", ".*",
        dedent("""\
               Unable to find any of the strings in the output of SigCheck:
                   "	Verified:" 
                   "	Verified:	Untrusted Root"
                   "	Verified:	Untrusted Authority"
                   "	Verified:	Untrusted Certificate"
                   "	Verified:	Malformed"
                   "	Verified:	Invalid Chain"
               meaning the file has an invalid/untrusted signature.
               The file might be modified or the signature is fake.
               """), 
    )
    AL_SigCheck_002 = Heuristic(
        "AL_SigCheck_002", "Expired Signature", ".*",
        dedent("""\
               If "	Verified:	Expired" is found in the SigCheck output,
               it means the file has an expired signature.
               """), 
    )
    AL_SigCheck_003 = Heuristic(
        "AL_SigCheck_003", "Trusted Signers", ".*",
        dedent("""\
               If "	Verified:	Signed" is found in the SigCheck output,
               and the signer is on a list of Authorised Signers.
               """), 
    )
    AL_SigCheck_004 = Heuristic(
        "AL_SigCheck_004", "NonFiltered Signers", ".*",
        dedent("""\
               If "	Verified:	Signed" is found in the SigCheck output,
               but the signer is not on list of Authorised Signers.
               """), 
    )
    AL_SigCheck_005 = Heuristic(
        "AL_SigCheck_005", "Sigcheck Unexpected Behavior", ".*",
        dedent("""\
               When the SigCheck tool returns unexpected results.
               """), 
    )

    SERVICE_CATEGORY = 'Filtering'
    SERVICE_DEFAULT_CONFIG = {
        'SIGCHECK_PATH': r'/al/support/sigcheck/sigcheck.exe',
        'SIGNTOOL_PATH': r'/al/support/sigcheck/signtool.exe',
        'SIGCHECK_TRUSTED_NAMES': [
            [
                "Microsoft Corporation",
                "Microsoft Code Signing PCA",
                "Microsoft Root Authority"
            ],
            [
                "Microsoft Corporation",
                "Microsoft Code Signing PCA",
                "Microsoft Root Certificate Authority"
            ],
            [
                "Microsoft Developer Platform Side-by-Side Assembly Publisher",
                "Microsoft Code Signing PCA",
                "Microsoft Root Certificate Authority"
            ],
            [
                "Microsoft Fusion Verification",
                "Microsoft Code Signing PCA",
                "Microsoft Root Certificate Authority"
            ],
            [
                "Microsoft Windows",
                "Microsoft Windows Verification PCA",
                "Microsoft Root Certificate Authority"
            ],
            [
                "Microsoft Windows Hardware Compatibility Publisher",
                "Microsoft Windows Hardware Compatibility PCA",
                "Microsoft Root Authority"
            ],
            [
                "Microsoft Windows Publisher",
                "Microsoft Windows Verification PCA",
                "Microsoft Root Certificate Authority"
            ],
            [
                "Microsoft Windows Side-by-Side Assembly Publisher",
                "Microsoft Code Signing PCA",
                "Microsoft Root Certificate Authority"
            ],

        ]
    }
    SERVICE_ACCEPTS = "(archive/.*|executable/.*|unknown)"
    SERVICE_DESCRIPTION = "This service checks for known good files signed by trusted signing authorities."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = 'FILTER'
    SERVICE_SUPPORTED_PLATFORMS = ['Windows']
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.75
    SERVICE_RAM_MB = 512

    def __init__(self, cfg=None):
        super(SigCheck, self).__init__(cfg)
        self.sigcheck_exe = None
        self.signtool_exe = None
        self.trusted_name_list = self.cfg.get('SIGCHECK_TRUSTED_NAMES', [])

    def start(self):
        # Validate configuration and tool locations.
        self.sigcheck_exe = self.cfg.get('SIGCHECK_PATH', '')
        if not os.path.isfile(self.sigcheck_exe):
            raise ConfigException('SIGCHECK_PATH (%s) is invalid or missing.' % self.sigcheck_exe)

        self.signtool_exe = self.cfg.get('SIGNTOOL_PATH', '')
        if not os.path.isfile(self.signtool_exe):
            raise ConfigException('SIGNTOOL_PATH (%s) is invalid or missing.' % self.signtool_exe)

    def execute(self, request):
        local_filename = request.download()
        proc = subprocess.Popen([self.sigcheck_exe, '-i', '-q', '-h', local_filename],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        stdout = unicode(stdout, 'mbcs')
        stderr = unicode(stderr, 'mbcs')
        if stderr:
            self.log.warn('SigCheck returned data on stderr: %s', stderr)
        request.result = self.populate_result(stdout.splitlines(), local_filename, request)

    def populate_result(self, current_lines, filename, request):
        result = Result()

        should_filter_out = False
        dump_sign_tool_output = False
        skip_detailed_output = False

        status_line = current_lines[1]
        if len(current_lines) <= 1 or status_line == "\tVerified:\tUnsigned":
            return result

        elif status_line.find("\tVerified:") != 0 or                   \
                status_line == "\tVerified:\tUntrusted Root" or           \
                status_line == "\tVerified:\tUntrusted Authority" or      \
                status_line == "\tVerified:\tUntrusted Certificate" or    \
                status_line == "\tVerified:\tMalformed" or                \
                status_line == "\tVerified:\tInvalid Chain":
            # This file has a signature but is not verified.
            result_section = ResultSection(
                score=SCORE.HIGH,
                title_text=("This file has an invalid/untrusted signature."
                            "The file might have been modified or the "
                            "signature is just a fake one.")
            )
            dump_sign_tool_output = True
            result.report_heuristic(SigCheck.AL_SigCheck_001)

        elif status_line == "\tVerified:\tExpired":
            # This file has a signature but is not verified.
            result_section = ResultSection(
                score=SCORE.LOW,
                title_text="This file has an expired signature."
            )
            dump_sign_tool_output = True
            result.report_heuristic(SigCheck.AL_SigCheck_002)

        elif status_line == "\tVerified:\tSigned":
            is_authorised_signers = False
            # Build the list of signers
            signers = []
            signers_tag_found = False
            i = 0
            while i < len(current_lines):
                if signers_tag_found:
                    if current_lines[i][0:2] == '\t\t':
                        # Skip the first two tabs.
                        signers.append(current_lines[i][2:])
                    else:
                        break
                elif current_lines[i].find("\tSigners:") == 0:
                    signers_tag_found = True
                i += 1

            for trusted_name_item in self.trusted_name_list:
                if trusted_name_item == signers:
                    is_authorised_signers = True
                    break

            if is_authorised_signers:
                result_section = ResultSection(
                    score=SCORE.NOT,
                    title_text="This file is signed with trusted signers"
                )
                result.report_heuristic(SigCheck.AL_SigCheck_003)
                should_filter_out = True

            else:
                result_section = ResultSection(
                    score=SCORE.INFO,
                    title_text="Signed with signers we don't automatically filter out"
                )
                result.report_heuristic(SigCheck.AL_SigCheck_004)

        else:
            self.log.error("The sigcheck output:\n%s\ncontained unexpected results %s" % ("\n".join(current_lines)))
            result_section = ResultSection(
                score=SCORE.MED,
                title_text="Unexpected result from sigcheck ... to investigate."
            )
            result.report_heuristic(SigCheck.AL_SigCheck_005)

        if should_filter_out and not request.ignore_filtering:
            request.drop()

        if skip_detailed_output:
            result.add_section(result_section)
            return result

        # Expand our result with the sigcheck output.
        self._add_sigcheck_output(current_lines, result_section)

        # Optionally expand our result with the signtool output.
        if dump_sign_tool_output:
            self._add_signtool_output(filename, result_section)

        result.add_section(result_section)
        return result

    @staticmethod
    def _add_sigcheck_output(tool_output, result_section):
        result_section.add_line("[SigCheck]")
        for line in tool_output:
            # File date is our copy file date so, not relevant at all.
            if not line.startswith('\t') or line.startswith("\tFile date:\t"):
                continue

            if 'MD5' in line:
                result_section.add_line("MD5: %s" % line.split(':')[1].strip())
            elif 'SHA1' in line:
                result_section.add_line("SHA1: %s" % line.split(':')[1].strip())
            else:
                # skip the '\t'
                result_section.add_line(line[1:])

    def _add_signtool_output(self, filename, result_section):
        # To provide a little more details ... let's run signtool as well when we find something
        # weird with sigcheck
        signtool_proc = subprocess.Popen([self.signtool_exe, 'verify', '/pa', '/v', '/a', filename],
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         cwd=os.path.dirname(self.signtool_exe))
        signtool_stdout, signtool_stderr = signtool_proc.communicate()
        
        result_section.add_line("\n[SignTool]")
        for line in chain(signtool_stdout.splitlines(), signtool_stderr.splitlines()):
            if 'SHA1' in line:
                result_section.add_line(line.split(':')[0] + ": " + line.split(':')[1].strip())
            if 'Verifying' in line:
                continue
            else:
                result_section.add_line(line)
