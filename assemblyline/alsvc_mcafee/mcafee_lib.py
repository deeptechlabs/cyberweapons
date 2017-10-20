"""
McAfee Command Line AntiVirus Python Wrapper.

This module contains system independent code for executing and processing the 
results of the McAfee Command Line AV Scanner.  It is originally targetted to linux but should be 
compatible with windows also with minimal modifications.

"""
import logging
import os
import re
import subprocess

from assemblyline.common.charset import safe_str
from assemblyline.al.common.av_result import AvScanResult
from xml.etree import cElementTree as ElementTree

DEFAULT_EXE = '/opt/al/support/mcafee/uvscan'
DEFAULT_DAT_DIRECTORY = '/opt/al/var/avdat/mcafee/'
DEFAULT_RESULT_FILE = 'results.xml'

log = logging.getLogger('assemblyline.svc.mcafee.common')

# McAfee exposes more command line options than are described here. This is a
# list of options that would most obviously be useful.
# Format: (local_name, cmdline_token, argument_type, description)
# Arguments of type bool are just passed as --TOKEN. (i.e there is no --TOKEN=True)
CMDLINE_DESCRIPTORS = (
    ('analyze', 'ANALYZE', bool, 'Turn on heuristic analysis for programs and macros.'),
    ('checklist', 'CHECKLIST', str, 'Scan list of files contained in <filename>.'),
    ('badlist', 'BADLIST', str, 'Filename and path for bad list log file.'),
    ('scanlist', 'FILE', str, 'Scan list of files contained in <filename>.'),
    ('mailbox', 'MAILBOX', bool, 'Scan inside plain text mailboxes.'),
    ('mime', 'MIME', bool, 'Scan inside MIME, UUE, XXE and BinHex files.'),
    ('silent', 'SILENT', bool, 'Disable all screen output.'),
    ('noboot', 'NOBOOT', bool, 'Do not scan boot sectors.'),
    ('timeout', 'TIMEOUT', int, 'Maximum time in seconds scanning a single file'),
    ('data_directory', 'DATA-DIRECTORY', str, 'Directory specifying location of DAT files.'),
    ('xmlpath', 'XMLPATH', str, 'Filename and path for XML log file.'),
    ('report_all', 'RPTALL', bool, 'Include all scanned files in the /REPORT file.'),
)


class McAfeeScanConfig(object):
    """
    Configuration for the McAfee Scanner. 
    This configuration will be used to generate an appropriate command-line for the scanner. 
    It will also validate the configuration values and host environment. 
    Currently this is only used internally to this module.
    """
    exe_path = DEFAULT_EXE
    analyze = False
    checklist = None
    badlist = None
    scanlist = None
    mailbox = True
    mime = True
    noboot = True
    timeout = 10
    silent = True
    data_directory = '.'
    xmlpath = DEFAULT_RESULT_FILE
    report_all = True

    def to_cmdline_windows(self):
        """Generate a Windows compatible command-line template for config."""
        return self._to_cmdline(r'/')

    def to_cmdline_unix(self):
        """Generate a Linux compatible command-line template for config."""
        return self._to_cmdline(r'--')

    def validate_or_raise(self):
        """Perform validation based on configuration."""
        if not self.data_directory or not os.path.isdir(self.data_directory):
            raise Exception(
                'Invalid or Missing DAT directory: {0}'.format(self.data_directory))
        if not self.exe_path or not os.path.exists(self.exe_path):
            raise Exception(
                'Invalid or Missing McAfee EXE: {0}'.format(self.exe_path))

    def _to_cmdline(self, delim):
        cmdargs = []
        for (prop_name, arg_name, arg_type, _arg_help) in CMDLINE_DESCRIPTORS:
            if hasattr(self, prop_name):
                if arg_type is str:
                    arg_value = getattr(self, prop_name)
                    if arg_value:
                        arg = "{0}{1}={2}".format(delim, arg_name, arg_value)
                        cmdargs.append(arg)
                elif arg_type is bool:
                    arg_value = getattr(self, prop_name)
                    if arg_value:
                        arg = "{0}{1}".format(delim, arg_name)
                        cmdargs.append(arg)
                elif arg_type is int:
                    arg_value = getattr(self, prop_name)
                    arg = "{0}{1}={2}".format(delim, arg_name, arg_value)
                    cmdargs.append(arg)
                else:
                    raise Exception('Unrecognized Argument type for {0}'.format(prop_name))
        return cmdargs


# XML definitions required for processing scan results.
ROOT_TAG = 'Uvscan'
CHILD_PREAMBLE = 'Preamble'
CHILD_FILE = 'File'
CHILD_TIME = 'Time'
CHILD_OPTIONS = 'Options'
CHILD_DATETIME = 'Date_Time'
ATTRIB_FILENAME = 'name'
ATTRIB_STATUS = 'status'
ATTRIB_VIRUS_NAME = 'virus-name'
ATTRIB_VIRUS_TYPE = 'detection-type'
CHILD_PRODUCT_NAME = 'Product_name'
CHILD_PRODUCT_VERSION = 'Version'
CHILD_ENGINE_VERSION = 'AV_Engine_version'
CHILD_DAT_VERSION = 'Dat_set_version'


class McAfeeResultParser(object):
    """
    Result parser for McAfee XML based result output. 
    Converts the McAfee XML result to a more python dictionary representation.
    """

    BAD_XML_CHARREF = re.compile('&#x[0-9][0-9];')

    def __init__(self, result_as_xml_string):
        # There is a bug in McAfee XML output.
        # Occasionally the mcafee xml result with have non escaped utf-8 characters
        # in the embedded filename etc that will not parse. remove them.
        result_as_xml_string = safe_str(re.sub(self.BAD_XML_CHARREF, 'INV', result_as_xml_string))
        root = ElementTree.fromstring(result_as_xml_string)  # @UndefinedVariable
        if root.tag != ROOT_TAG:
            raise Exception('Unexpected root in XML result: %s.' % root.tag)
        element_parsers = {
            CHILD_PREAMBLE: self._add_preamble,
            CHILD_DATETIME: self._ignore_element,
            CHILD_TIME: self._add_duration,
            CHILD_OPTIONS: self._ignore_element,
            CHILD_FILE: self._add_file_result,
        }
        self.preamble = None
        self.file_results = []
        for child in root:
            element_parsers.get(child.tag, self._handle_unexpected_element)(child)

    @staticmethod
    def _add_duration(element):
        log.debug('Scan took: %s' % str(element.attrib['value']))

    def _ignore_element(self, element):
        pass

    @staticmethod
    def _handle_unexpected_element(element):  # pylint: disable-msg=R0201
        log.warn('Unexpected element in result tree: %s', element.tag)
        return

    def _add_file_result(self, file_node):
        required_attributes = frozenset([ATTRIB_FILENAME, ATTRIB_STATUS])
        virus_attributes = frozenset([ATTRIB_VIRUS_NAME, ATTRIB_VIRUS_TYPE])
        # The file element has an 'attribute' dictionary that contains what 
        # we need in a decent format. Lets just validate that it has the 
        # attributes we expect then add to our result as is.
        if not required_attributes.issubset(file_node.attrib.keys()):
            log.warn('Skipping file element due to missing attribute. %s',
                     file_node.attrib)
            return
        # If this is a virus hit (i.e. status is not ok) we should also 
        # have virus name and virus type.
        if file_node.attrib[ATTRIB_STATUS] != 'ok':
            if not virus_attributes.issubset(file_node.attrib.keys()):
                log.warn('Skipping hit due to missing attribute. %s',
                         file_node.attrib)
                return
        # Otherwise we have the fields we need. We'll just pass along any other fields as well.
        self.file_results.append(file_node.attrib)

    def _add_preamble(self, preamble_element):
        required_children = [CHILD_PRODUCT_NAME, CHILD_PRODUCT_VERSION,
                             CHILD_PRODUCT_VERSION, CHILD_ENGINE_VERSION, CHILD_DAT_VERSION]
        children_of_interest = {name: None for name in required_children}
        for child in preamble_element:
            if child.tag in children_of_interest:
                children_of_interest[child.tag] = child.attrib['value']
        # At this point we should have extracted all fields of interest.
        for (key, value) in children_of_interest.iteritems():
            if value is None:
                log.warn('Preamble was missing a required field: %s', key)
        self.preamble = children_of_interest
        return

    def to_dictionary(self):
        return {'Preamble': self.preamble, 'FileResults': self.file_results}


class McAfeeScanner(object):
    def __init__(self, exe_path=DEFAULT_EXE, dat_path=DEFAULT_DAT_DIRECTORY, working_dir='.'):
        self._working_dir = working_dir
        self._config = McAfeeScanConfig()
        self._config.exe_path = exe_path
        self._config.data_directory = dat_path
        self._config.xmlpath = os.path.join(self._working_dir, DEFAULT_RESULT_FILE)
        self._config.validate_or_raise()

    def decompress_avdefinitions(self):
        # running the scanner with the decompress option
        # after an av update will decompress then saving cpu at the cost of disk.
        decompress_cmd = [self._config.exe_path,
                          '--DAT={}'.format(self._config.data_directory),
                          '--DECOMPRESS']
        p = subprocess.Popen(decompress_cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        return "Output:\n%s\n\nError:%s\n" % (out, err)

    def scan_files(self, file_paths):
        if not file_paths:
            return None

        mcafee_args = self._config.to_cmdline_unix()
        for fname in file_paths:
            mcafee_args.append(fname)

        cmd = [self._config.exe_path] + mcafee_args

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        exitcode = p.wait()
        if exitcode != 0 and exitcode != 13:
            log.error('McAfee \n stdout: %s \n stderr: %s', out, err)
            raise Exception('McAfee exited with non zero status: %s', exitcode)

        parsed_result = self._parse_xml_result(self._config.xmlpath)

        avscan_result = AvScanResult()
        preamble = parsed_result.get('Preamble', {})
        avscan_result.version_application = preamble.get('Version', 'Unknown')
        avscan_result.version_dats = preamble.get('Dat_set_version', 'Unknown')
        avscan_result.version_engine = preamble.get('AV_Engine_version', 'Unknown')

        for result in parsed_result.get('FileResults', []):
            is_virus = False
            embedded_file = virus_name = detection_type = ''
            reported_path = result.get('name')
            found = False
            for path in file_paths:
                if reported_path.startswith(path):
                    found = True
                    if len(reported_path) > len(path):
                        _sep, _head, embedded_file = reported_path.partition(path)
                    status = result.get('status', 'ok')
                    if status == 'infected':
                        is_virus = True
                        virus_name = result.get('virus-name')
                        detection_type = result.get('detection-type', '')
                    avscan_result.add_result(path, is_virus, virus_name, detection_type, embedded_file)
            if not found:
                log.warn("Couldn't find %s in %s", reported_path, file_paths)
        return avscan_result

    def get_version_info(self):
        ver_engine = 'unknown'
        ver_defs = 'unknown'
        version_cmd = [self._config.exe_path, '--DAT={}'.format(self._config.data_directory), '--VERSION']
        p = subprocess.Popen(version_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        for line in out.splitlines():
            if line.startswith('Dat set version:'):
                ver_defs = line.split(':')[1].strip()
            elif line.startswith('AV Engine version:'):
                ver_engine = line.split(':')[1].strip('. ')
        return 'Engine:%s Defs:%s' % (ver_engine, ver_defs)

    @staticmethod
    def _parse_xml_result(path):
        result_as_xml_string = open(path, 'r').read()
        try:
            parser = McAfeeResultParser(result_as_xml_string)
        except:
            import tempfile
            t = tempfile.NamedTemporaryFile(delete=False)
            t.write(result_as_xml_string)
            log.error("XML Parse failure. Saved content to temp location: %s", t.name)
            t.close()
            raise
        return parser.to_dictionary()
