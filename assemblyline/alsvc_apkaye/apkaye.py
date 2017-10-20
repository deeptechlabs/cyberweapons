import os
from subprocess import Popen, PIPE, call
from textwrap import dedent

from assemblyline.common.charset import safe_str
from assemblyline.common.net import is_valid_domain, is_valid_ip, is_valid_email
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE, TEXT_FORMAT, TAG_TYPE, TAG_WEIGHT
from al_services.alsvc_apkaye.static import ALL_ANDROID_PERMISSIONS, ISO_LOCALES
from assemblyline.al.service.base import ServiceBase


class APKaye(ServiceBase):
    SERVICE_ACCEPTS = "android/apk"
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_CPU_CORES = 1
    SERVICE_DEFAULT_CONFIG = {
        'APKTOOL_PATH': '/opt/al/support/apkaye/apktool_2.0.3.jar',
        'AAPT_PATH': '/opt/al/support/apkaye/aapt/aapt',
        'DEX2JAR_PATH': '/opt/al/support/apkaye/dex2jar-2.0/d2j-dex2jar.sh'
    }
    SERVICE_DESCRIPTION = "This service analyzes Android APKs. APKs are decompiled and inspected. Network " \
                          "indicators and information found in the APK manifest file is displayed."
    SERVICE_ENABLED = True
    SERVICE_RAM_MB = 512
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_DEFAULT_SUBMISSION_PARAMS = [
        {"default": False,
         "name": "resubmit_apk_as_jar",
         "type": "bool",
         "value": False}
    ]

    AL_APKaye_001 = Heuristic("AL_APKaye_001", "Embedded shell scripts", "android/apk",
                              dedent("""\
                                     One or more shell script is present inside the APK. Normal Android app should
                                     not have to use shell script to accomplish what they need to do.
                                     """))
    AL_APKaye_002 = Heuristic("AL_APKaye_002", "Embedded executable", "android/apk",
                              dedent("""\
                                     An ELF file was found inside the APK which means that this APK will try to run
                                     native code on the Android platform.
                                     """))
    AL_APKaye_003 = Heuristic("AL_APKaye_003", "Network indicator found", "android/apk",
                              dedent("""\
                                     A network indicator was found inside the APK. That does not mean the APK is bad
                                     but this APK will most likely try to reach that network indicator.
                                     """))

    AL_APKaye_004 = Heuristic("AL_APKaye_004", "Dangerous permission used", "android/apk",
                              dedent("""\
                                     This APK uses permissions that are deemed dangerous.
                                     """))

    AL_APKaye_005 = Heuristic("AL_APKaye_005", "Unknown permission used", "android/apk",
                              dedent("""\
                                     This APK uses permissions unknown permissions.
                                     """))

    AL_APKaye_006 = Heuristic("AL_APKaye_006", "No strings in APK", "android/apk",
                              dedent("""\
                                     There are absolutely no strings provided in this APK. This is highly unlikely for
                                     a normal APK.
                                     """))

    AL_APKaye_007 = Heuristic("AL_APKaye_007", "Low volume of strings in APK", "android/apk",
                              dedent("""\
                                     There are less that 50 strings in this APK which is unlikely for any APKs.
                                     """))

    AL_APKaye_008 = Heuristic("AL_APKaye_008", "Built for single language", "android/apk",
                              dedent("""\
                                     This APK was build for a single language. In our days, this is unlikely.
                                     """))

    AL_APKaye_009 = Heuristic("AL_APKaye_009", "Unsigned APK", "android/apk",
                              dedent("""\
                                     This APK is not signed. Signing an APK is required to publish on Google Play.
                                     """))

    AL_APKaye_010 = Heuristic("AL_APKaye_010", "Self-signed certificate", "android/apk",
                              dedent("""\
                                     This APK is self-signed.
                                     """))

    AL_APKaye_011 = Heuristic("AL_APKaye_011", "No country in certificate owner", "android/apk",
                              dedent("""\
                                     This APK's certificate has no country in the owner field.
                                     """))

    AL_APKaye_012 = Heuristic("AL_APKaye_012", "Certificate valid before first android release", "android/apk",
                              dedent("""\
                                     This APK's certificate is valid before the release date of the first
                                     android release (API v1 - 09/2008).
                                     """))

    AL_APKaye_013 = Heuristic("AL_APKaye_013", "Certificate valid more then 30 years", "android/apk",
                              dedent("""\
                                     APK's certificate is valid more then 30 years. This is highly unlikely.
                                     """))

    AL_APKaye_014 = Heuristic("AL_APKaye_014", "Invalid country code in certificate owner", "android/apk",
                              dedent("""\
                                     APK's certificate has an invalid country code.
                                     """))

    AL_APKaye_015 = Heuristic("AL_APKaye_015", "Non-conventinal certificate name.", "android/apk",
                              dedent("""\
                                     APK's certificate is not named CERT.RSA. Android studio, when building and APK,
                                     will name the certificate CERT.RSA.
                                     """))

    AL_APKaye_016 = Heuristic("AL_APKaye_016", "Certificate expired before it was even valid", "android/apk",
                              dedent("""\
                                     APK's certificate is expiring before the certificate validity date.
                                     """))

    def __init__(self, cfg):
        super(APKaye, self).__init__(cfg)
        self.apktool = cfg.get("APKTOOL_PATH", None)
        self.dex2jar = cfg.get("DEX2JAR_PATH", None)
        self.aapt = cfg.get("AAPT_PATH", None)

    def start(self):
        if not os.path.isfile(self.apktool) or not os.path.isfile(self.dex2jar) or not os.path.isfile(self.aapt):
            self.log.error("One of APKTOOL, AAPT and DEX2JAR is missing. The service will most likely fail.")

    def get_tool_version(self):
        return "APKTOOL: 2.0.3 - D2J: 2.0 - AAPT: 23.0.2"

    @staticmethod
    def validate_certs(apktool_out_dir, result):
        has_cert = False
        for root, _, files in os.walk(os.path.join(apktool_out_dir, "original", "META-INF")):
            for f in files:
                cur_file = os.path.join(root, f)
                stdout, stderr = Popen(["keytool", "-printcert", "-file", cur_file],
                                       stderr=PIPE, stdout=PIPE).communicate()
                if stdout:
                    if "keytool error" not in stdout:
                        has_cert = True
                        issuer = ""
                        owner = ""
                        country = ""
                        valid_from = ""
                        valid_to = ""
                        valid_year_end = 0
                        valid_year_start = 0
                        for line in stdout.splitlines():
                            if "Owner:" in line:
                                owner = line.split(": ", 1)[1]
                                country = owner.split("C=")
                                if len(country) != 1:
                                    country = country[1]
                                else:
                                    country = ""
                            if "Issuer:" in line:
                                issuer = line.split(": ", 1)[1]
                            if "Valid from:" in line:
                                valid_from = line.split(": ", 1)[1].split(" until:")[0]
                                valid_to = line.rsplit(": ", 1)[1]
                                valid_year_start = int(valid_from.split(" ")[-1])
                                valid_year_end = int(valid_to.split(" ")[-1])

                        result.add_tag(TAG_TYPE.ANDROID_CERT_START_DATE, valid_from, TAG_WEIGHT.HIGH)
                        result.add_tag(TAG_TYPE.ANDROID_CERT_END_DATE, valid_to, TAG_WEIGHT.HIGH)
                        result.add_tag(TAG_TYPE.ANDROID_CERT_ISSUER, issuer, TAG_WEIGHT.HIGH)
                        result.add_tag(TAG_TYPE.ANDROID_CERT_OWNER, owner, TAG_WEIGHT.HIGH)

                        res_cert = ResultSection(SCORE.NULL, "Certificate Analysis", body=safe_str(stdout),
                                                 parent=result, body_format=TEXT_FORMAT.MEMORY_DUMP)
                        if owner == issuer:
                            ResultSection(SCORE.LOW, "Certificate is self-signed.", parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_010)
                        if not country:
                            ResultSection(SCORE.HIGH, "Certificate owner has no country.", parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_011)
                        if valid_year_start < 2008:
                            ResultSection(SCORE.VHIGH, "Certificate valid before first android release.",
                                          parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_012)
                        if valid_year_start > valid_year_end:
                            ResultSection(SCORE.VHIGH, "Certificate expires before validity date starts.",
                                          parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_016)
                        if (valid_year_end - valid_year_start) > 30:
                            ResultSection(SCORE.HIGH, "Certificate valid more then 30 years.", parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_013)
                        if country:
                            # noinspection PyBroadException
                            try:
                                int(country)
                                is_int_country = True
                            except:
                                is_int_country = False

                            if len(country) != 2 or is_int_country:
                                ResultSection(SCORE.MED, "Invalid country code in certificate owner", parent=res_cert)
                                result.report_heuristic(APKaye.AL_APKaye_014)
                        if f != "CERT.RSA":
                            ResultSection(SCORE.HIGH,
                                          "Certificate name not using conventinal name: %s" % f,
                                          parent=res_cert)
                            result.report_heuristic(APKaye.AL_APKaye_015)

        if not has_cert:
            ResultSection(SCORE.HIGH, "This APK is not signed.", parent=result)
            result.report_heuristic(APKaye.AL_APKaye_009)

    @staticmethod
    def find_scripts_and_exes(apktool_out_dir, result):
        scripts = []
        executables = []
        for root, _, files in os.walk(os.path.join(apktool_out_dir, "assets")):
            for f in files:
                cur_file = os.path.join(root, f)
                proc = Popen(["file", cur_file], stdout=PIPE, stderr=PIPE)
                stdout, _ = proc.communicate()
                if "script" in stdout.lower():
                    scripts.append(cur_file.replace(os.path.join(apktool_out_dir, "assets"), 'assets'))
                if "elf" in stdout.lower():
                    executables.append(cur_file.replace(os.path.join(apktool_out_dir, "assets"), 'assets'))

        if scripts:
            res_script = ResultSection(SCORE.HIGH, "Shell scripts where found inside the APK", parent=result)
            for script in sorted(scripts)[:20]:
                res_script.add_line(script)
            if len(scripts) > 20:
                res_script.add_line("and %s more..." % (len(scripts) - 20))
            result.report_heuristic(APKaye.AL_APKaye_001)

        if executables:
            res_exe = ResultSection(SCORE.HIGH, "Executables where found inside the APK", parent=result)
            for exe in sorted(executables)[:20]:
                res_exe.add_line(exe)
            if len(executables) > 20:
                res_exe.add_line("and %s more..." % (len(executables) - 20))
            result.report_heuristic(APKaye.AL_APKaye_002)

    @staticmethod
    def find_network_indicators(apktool_out_dir, result):
        # Whitelist
        skip_list = [
            "android.intent",
            "com.google",
            "com.android",
        ]
        indicator_whitelist = [
            'google.to',
            'google.ttl',
            'google.delay',
            'google_tagmanager.db',
            'gtm_urls.db',
            'gtm.url',
            'google_tagmanager.db',
            'google_analytics_v4.db',
            'Theme.Dialog.Alert',
            'popupLocationInfo.gravity',
            'popupLocationInfo.displayId',
            'popupLocationInfo.left',
            'popupLocationInfo.top',
            'popupLocationInfo.right',
            'popupLocationInfo.bottom',
            'googleads.g.doubleclick.net',
            'ad.doubleclick.net',
            '.doubleclick.net',
            '.googleadservices.com',
            '.googlesyndication.com',
            'android.hardware.type.watch',
            'mraid.js',
            'google_inapp_purchase.db',
            'mobileads.google.com',
            'mobileads.google.com',
            'share_history.xml',
            'share_history.xml',
            'activity_choser_model_history.xml',
            'FragmentPager.SavedState{',
            'android.remoteinput.results',
            'android.people',
            'android.picture',
            'android.icon',
            'android.text',
            'android.title',
            'android.title.big',
            'FragmentTabHost.SavedState{',
            'android.remoteinput.results',
            'android.remoteinput.results',
            'android.remoteinput.results',
            'libcore.icu.ICU']
        file_list = []

        # Indicators
        url_list = []
        domain_list = []
        ip_list = []
        email_list = []

        # Build dynamic whitelist
        smali_dir = os.path.join(apktool_out_dir, "smali")
        for root, dirs, files in os.walk(smali_dir):
            if not files:
                continue
            else:
                skip_list.append(root.replace(smali_dir + "/", "").replace("/", "."))

            for cdir in dirs:
                skip_list.append(os.path.join(root, cdir).replace(smali_dir + "/", "").replace("/", "."))

        asset_dir = os.path.join(apktool_out_dir, "assets")
        if os.path.exists(asset_dir):
            for root, dirs, files in os.walk(asset_dir):
                if not files:
                    continue
                else:
                    for asset_file in files:
                        file_list.append(asset_file)
        skip_list = list(set(skip_list))

        # Find indicators
        proc = Popen(['grep', '-ER',
                      r'(([[:alpha:]](-?[[:alnum:]])*)\.)*[[:alpha:]](-?[[:alnum:]])+\.[[:alpha:]]{2,}',
                      smali_dir], stdout=PIPE, stderr=PIPE)
        grep, _ = proc.communicate()
        for line in grep.splitlines():
            file_path, line = line.split(":", 1)

            if "const-string" in line or "Ljava/lang/String;" in line:
                data = line.split("\"", 1)[1].split("\"")[0]
                data_low = data.lower()
                data_split = data.split(".")
                if data in file_list:
                    continue
                elif data in indicator_whitelist:
                    continue
                elif data.startswith("/"):
                    continue
                elif len(data_split[0]) < len(data_split[-1]) and len(data_split[-1]) > 3:
                    continue
                elif data_low.startswith("http://") or data_low.startswith('ftp://') or data_low.startswith('https://'):
                    url_list.append(data)
                elif data.startswith('android.') and data_low != data:
                    continue
                elif "/" in data and "." in data and data.index("/") < data.index("."):
                    continue
                elif " " in data:
                    continue
                elif data_split[0] in ['com', 'org', 'net', 'java']:
                    continue
                elif data_split[-1].lower() in ['so', 'properties', 'zip', 'read', 'id', 'store',
                                                'name', 'author', 'sh', 'soccer', 'fitness', 'news', 'video']:
                    continue
                elif data.endswith("."):
                    continue
                else:
                    do_skip = False
                    for skip in skip_list:
                        if data.startswith(skip):
                            do_skip = True
                            break

                    if do_skip:
                        continue

                    data = data.strip(".")

                    if is_valid_domain(data):
                        domain_list.append(data)
                    elif is_valid_ip(data):
                        ip_list.append(data)
                    elif is_valid_email(data):
                        email_list.append(data)

        url_list = list(set(url_list))
        for url in url_list:
            dom_ip = url.split("//")[1].split("/")[0]
            if ":" in dom_ip:
                dom_ip = dom_ip.split(":")[0]

            if is_valid_ip(dom_ip):
                ip_list.append(dom_ip)
            elif is_valid_domain(dom_ip):
                domain_list.append(dom_ip)

        ip_list = list(set(ip_list))
        domain_list = list(set(domain_list))
        email_list = list(set(email_list))

        if url_list:
            res_url = ResultSection(SCORE.NULL, "Found urls in the decompiled code", parent=result)
            count = 0
            for url in url_list:
                count += 1
                if count <= 20:
                    res_url.add_line(url)
                res_url.add_tag(TAG_TYPE.NET_FULL_URI, url, TAG_WEIGHT.MED)
            if count > 20:
                res_url.add_line("and %s more..." % (count - 20))

        if ip_list:
            res_ip = ResultSection(SCORE.NULL, "Found IPs in the decompiled code", parent=result)
            count = 0
            for ip in ip_list:
                count += 1
                if count <= 20:
                    res_ip.add_line(ip)
                res_ip.add_tag(TAG_TYPE.NET_IP, ip, TAG_WEIGHT.MED)
            if count > 20:
                res_ip.add_line("and %s more..." % (count - 20))

        if domain_list:
            res_domain = ResultSection(SCORE.NULL, "Found domains in the decompiled code", parent=result)
            count = 0
            for domain in domain_list:
                count += 1
                if count <= 20:
                    res_domain.add_line(domain)
                res_domain.add_tag(TAG_TYPE.NET_DOMAIN_NAME, domain, TAG_WEIGHT.MED)
            if count > 20:
                res_domain.add_line("and %s more..." % (count - 20))

        if email_list:
            res_email = ResultSection(SCORE.NULL, "Found email adresses in the decompiled code", parent=result)
            count = 0
            for email in email_list:
                count += 1
                if count <= 20:
                    res_email.add_line(email)
                res_email.add_tag(TAG_TYPE.NET_EMAIL, email, TAG_WEIGHT.MED)
            if count > 20:
                res_email.add_line("and %s more..." % (count - 20))

        if url_list or ip_list or domain_list or email_list:
            result.report_heuristic(APKaye.AL_APKaye_003)

    def analyse_apktool_output(self, apktool_out_dir, result):
        self.find_network_indicators(apktool_out_dir, result)
        self.find_scripts_and_exes(apktool_out_dir, result)
        self.validate_certs(apktool_out_dir, result)

    def run_apktool(self, apk, target_dir, resutl):
        apktool = Popen(["java", "-jar", self.apktool, "--output", target_dir, "d", apk],
                        stdout=PIPE, stderr=PIPE)
        apktool.communicate()
        if os.path.exists(target_dir):
            self.analyse_apktool_output(target_dir, resutl)

    @staticmethod
    def get_dex(apk, target):
        call(["unzip", "-o", apk, os.path.basename(target)], cwd=os.path.dirname(target))

    def resubmit_dex2jar_output(self, apk_file, target, result, request):
        dex = os.path.join(self.working_directory, "classes.dex")
        self.get_dex(apk_file, dex)
        if os.path.exists(dex):
            d2j = Popen([self.dex2jar, "--output", target, dex],
                        stdout=PIPE, stderr=PIPE)
            d2j.communicate()
            if os.path.exists(target):
                res_sec = ResultSection(SCORE.NULL, "Classes.dex file was recompiled as a JAR "
                                                    "and re-submitted for analysis")
                res_sec.add_line("JAR file resubmitted as: %s" % os.path.basename(target))
                request.add_extracted(target, "Dex2Jar output JAR file")
                result.add_section(res_sec)

    def run_appt(self, args):
        cmd_line = [self.aapt]
        cmd_line.extend(args)
        proc = Popen(cmd_line, stdout=PIPE, stderr=PIPE)
        return proc.communicate()

    def run_badging_analysis(self, apk_file, result):
        badging_args = ['d', 'badging', apk_file]
        badging, errors = self.run_appt(badging_args)
        if not badging:
            return
        res_badging = ResultSection(SCORE.NULL, "Android application details")
        libs = []
        permissions = []
        components = []
        features = []
        for line in badging.splitlines():
            if line.startswith("package: "):
                pkg_name = line.split("name='")[1].split("'")[0]
                pkg_version = line.split("versionCode='")[1].split("'")[0]
                res_badging.add_line("Package: %s v.%s" % (pkg_name, pkg_version))
                res_badging.add_tag(TAG_TYPE.ANDROID_PKG_NAME, pkg_name, TAG_WEIGHT.HIGH)

            if line.startswith("sdkVersion:"):
                min_sdk = line.split(":'")[1][:-1]
                res_badging.add_line("Min SDK: %s" % min_sdk)
                res_badging.add_tag(TAG_TYPE.ANDROID_MINSDK, min_sdk, TAG_WEIGHT.NULL)

            if line.startswith("targetSdkVersion:"):
                target_sdk = line.split(":'")[1][:-1]
                res_badging.add_line("Target SDK: %s" % target_sdk)
                res_badging.add_tag(TAG_TYPE.ANDROID_TARGET_SDK, target_sdk, TAG_WEIGHT.NULL)

            if line.startswith("application-label:"):
                label = line.split(":'")[1][:-1]
                res_badging.add_line("Default Label: %s" % label)
                res_badging.add_tag(TAG_TYPE.ANDROID_APP_LABEL, label, TAG_WEIGHT.MED)

            if line.startswith("launchable-activity:"):
                launch = line.split("name='")[1].split("'")[0]
                res_badging.add_line("Launchable activity: %s" % launch)
                res_badging.add_tag(TAG_TYPE.ANDROID_ACTIVITY, launch, TAG_WEIGHT.HIGH)

            if line.startswith("uses-library-not-required:"):
                lib = line.split(":'")[1][:-1]
                if lib not in libs:
                    libs.append(lib)

            if line.startswith("uses-permission:") or line.startswith("uses-implied-permission:"):
                perm = line.split("name='")[1].split("'")[0]
                if perm not in permissions:
                    permissions.append(perm)

            if line.startswith("provides-component:"):
                component = line.split(":'")[1][:-1]
                if component not in components:
                    components.append(component)

            if "uses-feature:" in line or "uses-implied-feature:" in line:
                feature = line.split("name='")[1].split("'")[0]
                if feature not in features:
                    features.append(feature)

        if libs:
            res_lib = ResultSection(SCORE.NULL, "Libraries used", parent=res_badging)
            for lib in libs:
                res_lib.add_line(lib)
                res_lib.add_tag(TAG_TYPE.ANDROID_USE_LIBRARY, lib, TAG_WEIGHT.MED)

        if permissions:
            res_permissions = ResultSection(SCORE.NULL, "Permissions used", parent=res_badging)
            dangerous_permissions = []
            unknown_permissions = []
            for perm in permissions:
                if perm in ALL_ANDROID_PERMISSIONS:
                    if 'dangerous' in ALL_ANDROID_PERMISSIONS[perm]:
                        dangerous_permissions.append(perm)
                    else:
                        res_permissions.add_line(perm)
                        res_permissions.add_tag(TAG_TYPE.ANDROID_PERMISSION, perm, TAG_WEIGHT.NULL)
                else:
                    unknown_permissions.append(perm)

            if dangerous_permissions:
                res_dangerous_perm = ResultSection(SCORE.HIGH, "Dangerous permissions used", parent=res_badging)
                for perm in dangerous_permissions:
                    res_dangerous_perm.add_line(perm)
                    res_dangerous_perm.add_tag(TAG_TYPE.ANDROID_PERMISSION, perm, TAG_WEIGHT.MED)
                result.report_heuristic(APKaye.AL_APKaye_004)

            if unknown_permissions:
                res_unknown_perm = ResultSection(SCORE.MED, "Unknown permissions used", parent=res_badging)
                for perm in unknown_permissions:
                    res_unknown_perm.add_line(perm)
                    res_unknown_perm.add_tag(TAG_TYPE.ANDROID_PERMISSION, perm, TAG_WEIGHT.LOW)
                result.report_heuristic(APKaye.AL_APKaye_005)

        if features:
            res_features = ResultSection(SCORE.NULL, "Features used", parent=res_badging)
            for feature in features:
                res_features.add_line(feature)
                res_features.add_tag(TAG_TYPE.ANDROID_FEATURE, feature, TAG_WEIGHT.LOW)

        if components:
            res_components = ResultSection(SCORE.NULL, "Components provided", parent=res_badging)
            for component in components:
                res_components.add_line(component)
                res_components.add_tag(TAG_TYPE.ANDROID_PROVIDES_COMPONENT, component, TAG_WEIGHT.LOW)

        result.add_section(res_badging)

    def run_strings_analysis(self, apk_file, result):
        string_args = ['d', 'strings', apk_file]
        strings, _ = self.run_appt(string_args)
        if not strings or strings == "String pool is unitialized.\n":
            res_strings = ResultSection(SCORE.VHIGH, "No strings where found in this APK. This is highly "
                                                     "unlikely and most-likely malicious.")
            result.report_heuristic(APKaye.AL_APKaye_006)
        else:
            config_args = ['d', 'configurations', apk_file]
            configs, _ = self.run_appt(config_args)
            languages = []
            for line in configs.splitlines():
                config = line.upper()
                if config in ISO_LOCALES:
                    languages.append(config)
                    result.add_tag(TAG_TYPE.ANDROID_LOCALE, config, TAG_WEIGHT.LOW)

            res_strings = ResultSection(SCORE.NULL, "Strings Analysis")

            data_line = strings.split("\n", 1)[0]
            count = int(data_line.split(" entries")[0].rsplit(" ", 1)[1])
            styles = int(data_line.split(" styles")[0].rsplit(" ", 1)[1])
            if count < 50:
                res_count = ResultSection(SCORE.HIGH, "Low volume of strings, this is suspicious.",
                                          parent=res_strings, body_format=TEXT_FORMAT.MEMORY_DUMP)
                res_count.body = safe_str(strings)
                result.report_heuristic(APKaye.AL_APKaye_007)

            if len(languages) < 2:
                ResultSection(SCORE.HIGH, "This app is not built for multiple languages. This is unlikely.",
                              parent=res_strings)
                result.report_heuristic(APKaye.AL_APKaye_008)

            res_strings.add_line("Total string count: %s" % count)
            res_strings.add_line("Total styles: %s" % styles)
            if languages:
                res_strings.add_line("Languages: %s" % ", ".join(languages))

        result.add_section(res_strings)

    def execute(self, request):
        if request.tag != "android/apk":
            request.result = Result()
            return

        result = Result()
        request.set_service_context(self.get_tool_version())

        apk = request.download()
        filename = os.path.basename(apk)
        d2j_out = os.path.join(self.working_directory, "%s.jar" % filename)
        apktool_out = os.path.join(self.working_directory, "%s_apktool" % filename)

        self.run_badging_analysis(apk, result)
        self.run_strings_analysis(apk, result)
        self.run_apktool(apk, apktool_out, result)
        if request.get_param('resubmit_apk_as_jar'):
            self.resubmit_dex2jar_output(apk, d2j_out, result, request)

        request.result = result
