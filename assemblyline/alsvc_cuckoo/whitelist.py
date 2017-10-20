# Whitelist of data that may come up in analysis that we should ignore.

import re

WHITELIST_APPLICATIONS = {
    'Acrobat Reader': r'c:\program files\adobe\reader 10.0\reader\acrord32.exe',
    'DrWatson': r'c:\progra~1\common~1\micros~1\dw\dw20.exe',
    'Excel': r'c:\program files\microsoft office\office12\excel.exe',
    'Internet Explorer': r'c:\program files\internet explorer\iexplore.exe',
    'PowerPoint': r'c:\program files\microsoft office\office11\powerpnt.exe',
    'Windows Explorer': r'c:\windows\explorer.exe',
    'Word': r'c:\program files\microsoft office\office12\winword.exe',
}

# These domains may be present due to benign activity on the host
WHITELIST_DOMAINS = {
    'Adobe': '.*\.adobe.com',
    'Android NTP': '.*\.android.pool.ntp.org',
    'Windows Time Server': 'time\.(microsoft|windows)\.com',
    'Microsoft IPv4To6': '.*\.?teredo.ipv6.microsoft.com',
    'Microsoft Watson': 'watson.microsoft.com',
    'Microsoft DNS Check': 'dms.msftncsi.com',
    'Microsoft IPv4 Check': 'www.msftncsi.com',
    'Microsoft IPv6 Check': 'ipv6.msftncsi.com',
    'Microsoft CRL server': 'crl.microsoft.com',
    'TCP Local': '.*\.local',
    'Unix Local': 'local',
    'Windows': '.*\.windows.com',
    'Ubuntu Update': 'changelogs.ubuntu.com',
    'Ubuntu Netmon': 'daisy.ubuntu.com',
    'Ubuntu NTP': 'ntp.ubuntu.com',
    "Windows Update": ".*\.windowsupdate.com",
    "Comodo": ".*\.comodoca.com",
    "Verisign": ".*\.verisign.com"
}

# Note: This list should be updated if we change our analysis network topology/addresses
WHITELIST_IPS = {
    'localhost': r'127.0.0.1',
    'Honeynet': r'169.169.169.169',
    'Windows SSDP': r'239.255.255.250',
    'Windows IGMP': r'224\..*',
    'local_net': r'10\..*',
    'local_net_2': r'192\.168.*',
}

WHITELIST_DROPPED = [
     "SharedDataEvents",
     "SharedDataEvents-journal",
     "AcroFnt09.lst",
     "AdobeSysFnt09.lst",
     "AdobeCMapFnt09.lst",
     "ACECache10.lst",
     "UserCache.bin",
     "desktop.ini",
     "sRGB Color Space Profile.icm",
     "is330.icm",
     "kodak_dc.icm",
     "R000000000007.clb",
     "JSByteCodeWin.bin",
     # adobe plugins
     "Accessibility.api",
     "AcroForm.api",
     "Annots.api",
     "Checker.api",
     "DigSig.api",
     "DVA.api",
     "eBook.api",
     "EScript.api",
     "HLS.api",
     "IA32.api",
     "MakeAccessible.api",
     "Multimedia.api",
     "PDDom.api",
     "PPKLite.api",
     "ReadOutLoad.api",
     "reflow.api",
     "SaveAsRTF.api",
     "Search5.api",
     "Search.api",
     "SendMail.api",
     "Spelling.api",
     "Updater.api",
     "weblink.api",
     "ADMPlugin.apl",
     # adobe annotations
     "Words.pdf",
     "Dynamic.pdf",
     "SignHere.pdf",
     "StandardBusiness.pdf",
     # adobe templates
     "AdobeID.pdf",
     "DefaultID.pdf",
     # adobe fonts
     "AdobePiStd.otf",
     "CourierStd.otf",
     "CourierStd-Bold.otf",
     "CourierStd-BoldOblique.otf",
     "CourierStd-Oblique.otf",
     "MinionPro-Bold.otf",
     "MinionPro-BoldIt.otf",
     "MinionPro-It.otf",
     "MinionPro-Regular.otf",
     "MyriadPro-Bold.otf",
     "MyriadPro-BoldIt.otf",
     "MyriadPro-It.otf",
     "MyriadPro-Regular.otf",
     "SY______.PFB",
     "ZX______.PFB",
     "ZY______.PFB",
     "SY______.PFM",
     "zx______.pfm",
     "zy______.pfm",
     # adobe cmap
     "Identity-H",
     "Identity-V",

     # Winword
     "msointl.dll",
     "Normal.dot",
     "~$Normal.dotm",
     "wwintl.dll",
     "Word11.pip",
     "Word12.pip",
     "shell32.dll",
     "oleacc.dll",

     # IE
     "index.dat",
]

WHITELIST_HASHES = [

    # ########## FILE MD5s ############

    # Adobe SharedDataEvents
    'ac6f81bbb302fd4702c0b6c3440a5331',
    '34c4dbd7f13cfba281b554bf5ec185a4',
    '578c03ad278153d0d564717d8fb3de1d',

    # Office Normal.dotm and temp files
    '05044fbab6ca6fd667f6e4a54469bd13',
    'e16d04c25249a64f47bf6f2709f21fbe',
    '5d4d94ee7e06bbb0af9584119797b23a',

    # GDIP Font Cache
    '7ad0077a4e63b28b3f23db81510143f9',

    # Empty Hash
    'd41d8cd98f00b204e9800998ecf8427e',

    # OfficeDiagnostic Info
    '534c811e6cf1146241126513810a389e',

    # ExcludeDictionary:
    'f3b25701fe362ec84616a93a45ce9998',

    # Inetsim exe
    'be5eae9bd85769bce02d6e52a4927bcd',

    # ######### OTHER HASHES ###########

    # CLSIDs SHA1 for a file that doesn't open, but pops up the
    # 'how do you want to open this file' dialog:
    'd3cbe4cec3b40b336530a5a8e3371fda7696a3b1',

]

GUID_PATTERN = r'{[A-F0-9]{8}\-([A-F0-9]{4}\-){3}[A-F0-9]{12}\}'

WHITELIST_COMMON_PATTERNS = {
    'Office Temp Files': r'\\~[A-Z]{3}%s\.tmp$' % GUID_PATTERN,
    'Meta Font': r'[A-F0-9]{7,8}\.(w|e)mf$',
    'IE Recovery Store': r'RecoveryStore\.%s\.dat$' % GUID_PATTERN,
    'IE Recovery Files': r'%s\.dat$' % GUID_PATTERN,
    'Doc Tmp': r'(?:[a-f0-9]{2}|\~\$)[a-f0-9]{62}\.(doc|xls|ppt)x?$',
    'CryptnetCache': r'AppData\\[^\\]+\\MicrosoftCryptnetUrlCache\\',
    'Cab File': r'\\Temp\\Cab....\.tmp',
    'Office File': r'\\Microsoft\\OFFICE\\DATA\\[a-z0-9]+\.dat$',
    'Internet file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.MSO\\',
    'Word file': r'AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.Word\\~WRS',
    'Word Temp Files': r'\\Temp\\~$[a-f0-9]+\.doc',
    'Office Blocks': r'\\Microsoft\\Document Building Blocks\\[0-9]{4}\\',
    'Office ACL': r'AppData\\Roaming\\MicrosoftOffice\\.*\.acl$',
    'Office Dictionary': r'AppData\\Roaming\\Microsoft\\UProof\\CUSTOM.DIC$',
    'Office Form': r'AppData\\Local\\Temp\\Word...\\MSForms.exd$'
}


def match(data, sigs):
    for name, sig in sigs.iteritems():
        if re.match(sig, data):
            return name
    return None


def wlist_check_app(application):
    return match(application, WHITELIST_APPLICATIONS)


def wlist_check_domain(domain):
    return match(domain, WHITELIST_DOMAINS)


def wlist_check_ip(ip):
    return match(ip, WHITELIST_IPS)


def wlist_check_dropped(name):
    if name in WHITELIST_DROPPED:
        return True
    elif match(name, WHITELIST_COMMON_PATTERNS):
        return True
    return False


def wlist_check_hash(filehash):
    if filehash in WHITELIST_HASHES:
        return True
    return False
