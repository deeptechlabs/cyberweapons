import hashlib
import logging
import os
import zipfile
from subprocess import PIPE, Popen
from textwrap import dedent

from assemblyline.common.charset import translate_str
from assemblyline.common.hexdump import hexdump
from assemblyline.common.reaper import set_death_signal
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common import forge

G_LAUNCHABLE_EXTENSIONS = [
    'BAT',  # DOS/Windows batch file
    'CMD',  # Windows Command
    'COM',  # DOS Command
    'EXE',  # DOS/Windows executable
    'DLL',  # Windows library
    'LNK',  # Windows shortcut
    'SCR'   # Windows screensaver
]

APPLET = 'applet'
APPLET_MZ = 'mz_in_applet'

Classification = forge.get_classification()


class NotJARException(Exception):
    pass


# noinspection PyBroadException
class Espresso(ServiceBase):
    AL_Espresso_001 = Heuristic("AL_Espresso_001", "Embedded PE", "java/jar",
                                dedent("""\
                                       If the first two bytes of the JAR file are MZ there is an embedded
                                       executable detected.
                                       """))
    AL_Espresso_002 = Heuristic("AL_Espresso_002", "Launchable File in JAR", "java/jar",
                                dedent("""\
                                       If the file path has any of the following extensions:
                                           'BAT' - DOS/Windows batch file
                                           'CMD' - Windows Command
                                           'COM' - DOS Command
                                           'EXE' - DOS/Windows executable
                                           'DLL' - Windows library
                                           'LNK' - Windows shortcut
                                           'SCR' - Windows screensaver
                                       then there is a launchable file found inside the JAR.
                                       """))

    AL_Espresso_003 = Heuristic("AL_Espresso_003", "Encoding and Magic Bytes", "java/jar",
                                dedent("""\
                                       The file doesnt have the normal class file magic bytes.
                                       """))
    AL_Espresso_004 = Heuristic("AL_Espresso_004", "java/applet/Applet", "java/jar",
                                dedent("""\
                                       Looking for the string "java/applet/Applet" in the file
                                       """))
    AL_Espresso_005 = Heuristic("AL_Espresso_005", "ClassLoader", "java/jar",
                                dedent("""\
                                       Looking for the string "ClassLoader" in the file
                                       """))
    AL_Espresso_006 = Heuristic("AL_Espresso_006", "/security/", "java/jar",
                                dedent("""\
                                       Looking for the string "/security/" in the file
                                       """))
    AL_Espresso_007 = Heuristic("AL_Espresso_007", "net/URL", "java/jar",
                                dedent("""\
                                       Looking for the string "net/URt" in the file
                                       """))
    AL_Espresso_008 = Heuristic("AL_Espresso_008", "java/lang/Runtime", "java/jar",
                                dedent("""\
                                       Looking for the string "java/lang/Runtime" in the file
                                       """))

    SERVICE_ACCEPTS = 'java/jar'
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_DESCRIPTION = "This service analyzes Java JAR files. All classes are extracted, decompiled and " \
                          "analyzed for malicious behavior."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.8
    SERVICE_RAM_MB = 1024
    SERVICE_TIMEOUT = 180

    SERVICE_DEFAULT_CONFIG = {
        'CFR_PATH': '/opt/al/support/cfr/cfr.jar',
    }

    def __init__(self, cfg=None):
        super(Espresso, self).__init__(cfg)
        self.cfr = self.cfg.get('CFR_PATH')
        self.applet_found = 0
        self.classloader_found = 0
        self.security_found = 0
        self.url_found = 0
        self.runtime_found = 0

    def get_tool_version(self):
        return "CFR: 0.110"

    def start(self):
        if not os.path.isfile(self.cfr):
            self.log.error("CFR executable is missing. Service install likely failed.")

    def jar_extract(self, filename, dest_dir):
        zf = None
        try:
            zf = zipfile.ZipFile(filename, "r")

            # Make sure this is actually a JAR
            unknown_charset_counter = 0
            for zfname in zf.namelist():
                uni_zfname = ""
                try:
                    zf_info = zf.getinfo(zfname)

                    if not zf_info.orig_filename.endswith('\\') and not zf_info.orig_filename.endswith('/'):
                        char_enc_guessed = translate_str(zfname)
                        uni_zfname = char_enc_guessed['converted']

                        if char_enc_guessed['encoding'] == 'unknown':
                            uni_zfname = u'unknown_charset_filename_%d' % unknown_charset_counter
                            unknown_charset_counter += 1

                        # creating the directory has problems if the filename
                        # starts with a /, strip it off.
                        if uni_zfname.startswith("/"):
                            uni_zfname = uni_zfname[1:]

                        unzipped_filename = os.path.normpath(os.path.join(dest_dir, uni_zfname))
                        zf_content = zf.read(zfname)

                        if not os.path.exists(os.path.dirname(unzipped_filename)):
                            os.makedirs(os.path.dirname(unzipped_filename))

                        try:
                            o = open(unzipped_filename, 'wb')
                        except:
                            # just in case there was invalid char ...
                            uni_zfname = u'unknown_charset_filename_%d' % unknown_charset_counter
                            unknown_charset_counter += 1
                            unzipped_filename = os.path.normpath(os.path.join(dest_dir, uni_zfname))
                            o = open(unzipped_filename, 'wb')
                        o.write(zf_content)
                except Exception, e:
                    self.log.exception("Failed at extracting files from the JAR (%s). Error: %s" % (
                        filename.encode('utf-8') + "::" + uni_zfname, e))
                    return False
                finally:
                    try:
                        o.close()
                    except:
                        pass

        except (IOError, zipfile.BadZipfile):
            self.log.info("Not a ZIP File or Corrupt ZIP File: %s" % filename)
            return False
        except Exception, e:
            if type(e) == NotJARException:
                self.log.info("Not a JAR File: %s" % filename)
                raise

            self.log.exception("Caught an exception while analysing the file %s. [%s]" % (filename, e))
            return False
        finally:
            try:
                zf.close()
            except:
                pass

        return True

    def decompile_to_str(self, path_to_file):
        decompiled_path = self.find_decompiled_file(path_to_file)
        if decompiled_path:
            with open(decompiled_path, "rb") as decompiled_file:
                return decompiled_file.read()
        else:
            cfr = Popen(["java", "-jar", self.cfr, path_to_file], stdout=PIPE, stderr=PIPE,
                        preexec_fn=set_death_signal())
            stdout, _ = cfr.communicate()

            if len(stdout) > 0 and "Decompiled with CFR" in stdout[:0x24]:
                return stdout
            else:
                return None

    def decompile_class(self, path_to_file, new_files):
        # Decompile file
        decompiled = self.decompile_to_str(path_to_file)

        if decompiled:
            decompiled_path = self.find_decompiled_file(path_to_file)
            if not decompiled_path:
                decompiled_path = path_to_file.replace(".class", ".java").replace(".deob", "")
                java_handle = open(decompiled_path, "wb")
                java_handle.write(decompiled)
                java_handle.close()

            new_files.append((path_to_file, decompiled_path))
            return len(decompiled), hashlib.sha1(decompiled).hexdigest(), os.path.basename(decompiled_path)
        else:
            return 0, "", ""

    @staticmethod
    def find_decompiled_file(class_file):
        decompiled_file = class_file.replace("_extracted", "_decompiled").replace(".class", ".java")
        if os.path.exists(decompiled_file):
            return decompiled_file
        return None

    def do_class_analysis(self, data):
        has_interesting_attributes = False
        if "java/applet/Applet" in data:
            self.applet_found += 1
            has_interesting_attributes = True

        if "ClassLoader" in data:
            self.classloader_found += 1
            has_interesting_attributes = True

        if "/security/" in data:
            self.security_found += 1
            has_interesting_attributes = True

        if "net/URL" in data:
            self.url_found += 1
            has_interesting_attributes = True

        if "java/lang/Runtime" in data:
            self.runtime_found += 1
            has_interesting_attributes = True

        return has_interesting_attributes

    # noinspection PyUnusedLocal
    def analyse_class_file(self, file_res, cf, cur_file, cur_file_path, start_bytes, imp_res_list, supplementary_files):
        if start_bytes[:4] == "\xCA\xFE\xBA\xBE":
            cur_file.seek(0)
            cur_file_full_data = cur_file.read()

            # Analyse file for suspicious funtions
            if self.do_class_analysis(cur_file_full_data):
                self.decompile_class(cur_file_path, supplementary_files)

        else:
            # Could not deobfuscate
            cur_file.seek(0)
            first_256 = cur_file.read(256)

            ob_res = {"score": SCORE["VHIGH"], "text": ["Class file ", cf,
                                                        " doesn't have the normal class files "
                                                        "magic bytes. The file was re-submitted for analysis."
                                                        " Here are the first 256 bytes "
                                                        "of the file:"], "files": [cur_file_path],
                      "lines": [], "children": [], "tags": [],
                      "score_condition": None, "condition": None, "type": TEXT_FORMAT.MEMORY_DUMP}
            ob_res['lines'].append(hexdump(first_256))
            ob_res['tags'].append({"type": TAG_TYPE['FILE_SUMMARY'],
                                   "text": "Suspicious Java class", "score": TAG_WEIGHT['LOW']})
            imp_res_list.append(ob_res)
            file_res.report_heuristic(Espresso.AL_Espresso_003)

    def decompile_jar(self, path_to_file, target_dir):
        cfr = Popen(["java", "-jar", self.cfr, "--analyseas", "jar", "--outputdir", target_dir, path_to_file],
                    stdout=PIPE, stderr=PIPE, preexec_fn=set_death_signal())
        cfr.communicate()

    def execute(self, request):
        request.result = Result()
        request.set_service_context(self.get_tool_version())
        temp_filename = request.download()
        filename = os.path.basename(temp_filename)
        extract_dir = os.path.join(self.working_directory, "%s_extracted" % filename)
        decompiled_dir = os.path.join(self.working_directory, "%s_decompiled" % filename)
        file_res = request.result
        new_files = []
        supplementary_files = []
        imp_res_list = []
        res_list = []

        if request.tag == "java/jar":
            self.decompile_jar(temp_filename, decompiled_dir)
            if self.jar_extract(temp_filename, extract_dir):
                # Analysis properties
                self.classloader_found = 0
                self.security_found = 0
                self.url_found = 0
                self.runtime_found = 0
                self.applet_found = 0

                for root, _, files in os.walk(extract_dir.encode('utf-8')):
                    logging.info("Extracted: %s - %s" % (root, files))
                    for cf in files:
                        cur_file_path = os.path.join(root.decode('utf-8'), cf.decode('utf-8'))
                        cur_file = open(cur_file_path, "rb")
                        start_bytes = cur_file.read(24)

                        ##############################
                        # Executables in JAR
                        ##############################
                        cur_ext = os.path.splitext(cf)[1][1:].upper()
                        if start_bytes[:2] == "MZ":
                            mz_res = {"score": SCORE["VHIGH"],
                                      "text": ["Embedded executable file found: ",
                                               cf, ". There may be a malicious intent."],
                                      "files": [], "lines": [], "children": [], "tags": [],
                                      "score_condition": APPLET_MZ, "condition": None}
                            mz_res['tags'].append({"type": TAG_TYPE['FILE_SUMMARY'], "text": "Embedded PE",
                                                   "score": TAG_WEIGHT['LOW']})
                            file_res.report_heuristic(Espresso.AL_Espresso_001)
                            imp_res_list.append(mz_res)
                        ##############################
                        # Launchable in JAR
                        ##############################
                        elif cur_ext in G_LAUNCHABLE_EXTENSIONS:
                            l_res = {"score": SCORE["VHIGH"], "text": ["Launch-able file type found: ",
                                                                       cf, ". There may be a malicious intent."],
                                     "files": [], "lines": [],
                                     "children": [], "tags": [], "score_condition": APPLET_MZ, "condition": None}
                            l_res['tags'].append({"type": TAG_TYPE['FILE_SUMMARY'], "text": "Launch-able file in JAR",
                                                  "score": TAG_WEIGHT['LOW']})
                            file_res.report_heuristic(Espresso.AL_Espresso_002)
                            imp_res_list.append(l_res)

                        if cf.upper().endswith(".CLASS"):
                            self.analyse_class_file(file_res, cf, cur_file, cur_file_path,
                                                    start_bytes, imp_res_list, supplementary_files)

                        try:
                            cur_file.close()
                        except:
                            pass

                # Add file Analysis results to the list
                cl_score = 0
                if self.runtime_found > 0:
                    cl_score += SCORE["MED"]
                    file_res.report_heuristic(Espresso.AL_Espresso_008)
                if self.applet_found > 0:
                    cl_score += SCORE["MED"]
                    file_res.report_heuristic(Espresso.AL_Espresso_004)
                if self.classloader_found > 0:
                    cl_score += SCORE["LOW"]
                    file_res.report_heuristic(Espresso.AL_Espresso_005)
                if self.security_found > 0:
                    cl_score += SCORE["LOW"]
                    file_res.report_heuristic(Espresso.AL_Espresso_006)
                if self.url_found > 0:
                    cl_score += SCORE["LOW"]
                    file_res.report_heuristic(Espresso.AL_Espresso_007)

                res = ResultSection(0, "Analysis of the JAR file")
                if cl_score > 0:
                    res.add_line("All suspicious class files where saved as supplementary files.")
                res_class = ResultSection(cl_score, "[Suspicious classes]", parent=res)
                res_class.add_line("java/lang/Runtime: %s" % self.runtime_found)
                res_class.add_line("java/applet/Applet: %s" % self.applet_found)
                res_class.add_line("java/lang/ClassLoader: %s" % self.classloader_found)
                res_class.add_line("java/security/*: %s" % self.security_found)
                res_class.add_line("java/net/URL: %s" % self.url_found)
                res_list.append(res)

        # Add results if any
        self.recurse_add_res(file_res, imp_res_list, new_files)
        for res in res_list:
            file_res.add_section(res)

        # Submit embedded files
        if len(new_files) > 0:
            new_files = sorted(list(set(new_files)))
            txt = "Extracted from %s file %s" % ("JAR", filename)
            for embed in new_files:
                request.add_extracted(embed, txt,
                                      embed.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""))

        if len(supplementary_files) > 0:
            supplementary_files = sorted(list(set(supplementary_files)))
            for original, decompiled in supplementary_files:
                txt = "Decompiled %s" % original.replace(extract_dir + "/", "").replace(decompiled_dir + "/", "")
                request.add_supplementary(decompiled, txt,
                                          decompiled.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""))

    def recurse_add_res(self, file_res, res_list, new_files, parent=None):
        for res_dic in res_list:
            # Check if condition is OK
            if self.pass_condition(res_dic["condition"]):
                res_dic['score'] = self.score_alteration(res_dic['score_condition'], res_dic['score'])
                res = ResultSection(res_dic['score'], title_text=res_dic['text'],
                                    classification=res_dic.get('classification', Classification.UNRESTRICTED),
                                    parent=parent, body_format=res_dic.get('type', None))
                # Add Tags
                for res_tag in res_dic['tags']:
                    file_res.add_tag(res_tag['type'], res_tag['text'], res_tag['score'],
                                     classification=res_tag.get('classification', Classification.UNRESTRICTED))
                # Add Line
                for res_line in res_dic['lines']:
                    res.add_line(res_line)
                # File for resubmit
                for res_file in res_dic['files']:
                    if isinstance(res_file, tuple):
                        res_file = res_file[1]
                    new_files.append(res_file)

                # Recurse on children
                self.recurse_add_res(file_res, res_dic["children"], new_files, res)

                # Add to file res if root result
                if parent is None:
                    file_res.add_section(res)

    def pass_condition(self, condition):
        if condition is None:
            return True
        if condition == APPLET:
            if self.applet_found > 0:
                return True

        return False

    def score_alteration(self, score_condition, score):
        if score_condition is None:
            return score
        if score_condition == APPLET_MZ:
            if self.applet_found > 0:
                return 500
            else:
                return 100
