#!/usr/bin/env python

""" Metadata Anomaly Detection service. 

This service is intended to look for anomalies based on metadata only.
It does not require fetching the actual sample.
"""

import os
import posixpath
import re
from assemblyline.common.charset import remove_bidir_unicode_controls
from assemblyline.common.charset import wrap_bidir_unicode_string
from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.common.result import TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase

# This list is incomplete. Feel free to add entries. Must be uppercase
G_LAUNCHABLE_EXTENSIONS = [
    'AS',  # Adobe ActioonScript
    'BAT',  # DOS/Windows batch file
    'CMD',  # Windows Command
    'COM',  # DOS Command
    'EXE',  # DOS/Windows executable
    'DLL',  # Windows library
    'INF',  # Windows autorun
    'JS',  # JavaScript
    'LNK',  # Windows shortcut
    'SCR'  # Windows screensaver
]

# This list is incomplete. Feel free to add entries. Must be uppercase
G_BAIT_EXTENSIONS = [
    'BMP',  # Bitmap image
    'DOC',  # MS Word document
    'DOCX',  # MS Word document
    'DOT',  # MS Word template
    'JPG',  # JPEG image
    'JPEG',  # JPEG image
    'PDF',  # Acrobat PDF
    'PNG',  # Image
    'PPT',  # MS PowerPoint
    'TXT',  # Plain old text doc
    'XLS',  # MS spreadsheet
    'ZIP'  # Compressed file
]

# Reversed extensions are used in unicode extension hiding attacks
G_BAIT_EXTENSIONS += [file_ext[::-1] for file_ext in G_BAIT_EXTENSIONS]


class MetaPeek(ServiceBase):
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DEFAULT_CONFIG = {
    }
    SERVICE_DESCRIPTION = "This service checks submission metadata for indicators of potential malicious" \
                          " behavior (double file extenstions, ...)"
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = 'SECONDARY'  # run in secondary so we have more metadata
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.05
    SERVICE_RAM_MB = 64

    def __init__(self, cfg=None):
        super(MetaPeek, self).__init__(cfg)

    def execute(self, request):
        if not request.path:
            request.result = Result()
            return
        filename = posixpath.basename(request.path)
        request.result = self.check_file_name_anomalies(filename)
        return

    @staticmethod
    def fna_check_double_extension(filename):
        """ 
            Double extension
            A very simple check. If we have two short file extensions 
            back-to-back, with the last one launchable
        """

        file_ext_min = 2  # shortest extension we care about, excluding the '.'
        file_ext_max = 4  # longest extension we care about, excluding the '.'

        _, file_ext_1 = os.path.splitext(filename)
        file_ext_1 = remove_bidir_unicode_controls(file_ext_1.strip())
        # Ignore files with a '.' but nothing after
        if file_ext_min < len(file_ext_1) <= file_ext_max + 1:
            _, file_ext_2 = os.path.splitext(
                filename[:len(filename) - len(file_ext_1)])
            file_ext_2 = remove_bidir_unicode_controls(file_ext_2.strip())
            if file_ext_min < len(file_ext_2) <= file_ext_max + 1:
                if file_ext_1[1:].upper() in G_LAUNCHABLE_EXTENSIONS and file_ext_2[1:].upper() in G_BAIT_EXTENSIONS:
                    return True, file_ext_1

        return False, file_ext_1

    @staticmethod
    def fna_check_empty_filename(filename, f_ext):
        """ 
            Check for file names with extension only (".exe", ...etc). 
            This could be used with a path to look legit (e.g. "/Explorer/.exe")
            This also applies to file names that are all whitespaces + extension
        """

        if len(f_ext) > 0:
            filename_no_ext = filename[:len(filename) - len(f_ext)]
            # Also catch file names that are all spaces
            if len(filename_no_ext) == 0 or filename_no_ext.isspace():
                if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                    return True

        return False

    @staticmethod
    def fna_check_filename_ws(filename, f_ext):
        """ 
            File names with long sequences of whitespaces
            (for now, only spaces and tabs are counted)
            Also detect fillers such as: "!@#$%^&()_+*"
        """

        ws_count = len(re.findall('[- \t!@#$^&()=+*%]', filename))
        # More than half of file name is whitespaces? 
        # At least 10 whitespaces altogether.
        if (ws_count << 1) > len(filename) and ws_count >= 10:
            if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                return True

        return False

    @staticmethod
    def fna_check_unicode_bidir_ctrls(filename, f_ext):
        """ Detect Unicode RTLO
            This attack vector could use any combination of unicode values: 
            0x202E (RTL Override), 0x202B (RTL Embedding), # 0x202D (LTR 
            Override), or 0x202A (LTR Embedding). It is used to hide the 
            executible extension of a file. Although not used before in 
            malware, 0x200E (LTR Mark) and 0x200F (RTL Mark) are also checked 
            as they can potentially be used.
        """

        if type(filename) == type(unicode()):
            re_obj = re.search(ur'[\u202E\u202B\u202D\u202A\u200E\u200F]',
                               filename)
            if re_obj is not None and len(re_obj.group()) > 0:
                if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                    return True

        return False

    def check_file_name_anomalies(self, filename):
        """ Filename anomalies detection"""

        is_double_ext, f_ext = self.fna_check_double_extension(filename)
        is_empty_filename = self.fna_check_empty_filename(filename, f_ext)
        too_many_whitespaces = self.fna_check_filename_ws(filename, f_ext)
        has_unicode_ext_hiding_ctrls = self.fna_check_unicode_bidir_ctrls(filename, f_ext)

        file_res = Result()

        fna_score = SCORE.NULL
        if too_many_whitespaces:
            fna_score = fna_score + SCORE.VHIGH
        if is_double_ext:
            fna_score = fna_score + SCORE.VHIGH
        if has_unicode_ext_hiding_ctrls:
            fna_score = fna_score + SCORE.VHIGH
        if is_empty_filename:
            fna_score = fna_score + SCORE.VHIGH

        if fna_score > 0:
            res = ResultSection(fna_score, "File Name Anomalies:")

            if is_double_ext:
                res.add_line('Double file extension')
                file_res.add_tag(TAG_TYPE['FILENAME_ANOMALIES'],
                                 'DOUBLE_FILE_EXTENSION',
                                 TAG_WEIGHT["NULL"], usage='IDENTIFICATION')
                file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                 'Double file extension',
                                 TAG_WEIGHT["NULL"], usage='IDENTIFICATION')
            if too_many_whitespaces:
                res.add_line('File name has too many whitespaces, possibly masking its actual extension')
                file_res.add_tag(TAG_TYPE['FILENAME_ANOMALIES'],
                                 'TOO_MANY_WHITESPACES',
                                 TAG_WEIGHT['NULL'], usage='IDENTIFICATION')
                file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                 'File name has too many whitespaces',
                                 TAG_WEIGHT["NULL"], usage='IDENTIFICATION')
            if has_unicode_ext_hiding_ctrls:
                res.add_line('Launchable file extension is hidden using a Unicode bidirectional control')
                file_res.add_tag(TAG_TYPE['FILENAME_ANOMALIES'],
                                 'UNICODE_EXTENSION_HIDING',
                                 TAG_WEIGHT['NULL'], usage='IDENTIFICATION')
                file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                 'Real file extension hidden using unicode trickery',
                                 TAG_WEIGHT["NULL"], usage='IDENTIFICATION')
            if is_empty_filename:
                res.add_line('File name is empty or all whitespaces')
                file_res.add_tag(TAG_TYPE['FILENAME_ANOMALIES'],
                                 'FILENAME_EMPTY_OR_ALL_SPACES',
                                 TAG_WEIGHT['NULL'], usage='IDENTIFICATION')
                file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                 'File name is empty or all whitespaces',
                                 TAG_WEIGHT["NULL"], usage='IDENTIFICATION')

                # Tag filename as it might be of interest
            # Also add a line with "actual" file name
            file_res.add_tag(TAG_TYPE['FILE_NAME'],
                             filename,
                             TAG_WEIGHT['NULL'], usage='IDENTIFICATION')

            # Remove Unicode controls, if any, for reporting
            fn_no_controls = ''.join(c for c in filename
                                     if c not in [u'\u202E', u'\u202B', u'\u202D',
                                                  u'\u202A', u'\u200E', u'\u200F'])

            res.add_line('Actual File Name: \'%s\'' %
                         wrap_bidir_unicode_string(fn_no_controls))

            file_res.add_result(res)

        return file_res
