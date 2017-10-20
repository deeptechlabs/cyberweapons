import os
from assemblyline.common.path import modulepath

PRIORITIES = {
    'low': 100,
    'medium': 200,
    'high': 300,
    'critical': 400,
}

RECOGNIZED_TAGS = {
    'android/apk': True,
    'android/dex': True,
    'android/resource': True,
    'android/xml': True,
    'archive/7-zip': True,
    'archive/ace': True,
    'archive/ar': True,
    'archive/audiovisual/flash': True,
    'archive/bzip2': True,
    'archive/cabinet': True,
    'archive/cart': True,
    'archive/chm': True,
    'archive/cpio': True,
    'archive/gzip': True,
    'archive/iso': True,
    'archive/lzma': True,
    'archive/rar': True,
    'archive/tar': True,
    'archive/tnef': True,
    'archive/unknown': True,
    'archive/xz': True,
    'archive/zip': True,
    'audiovisual/afs': True,
    'audiovisual/acb': True,
    'audiovisual/flash': True,
    'audiovisual/fsb': True,
    'audiovisual/unknown': True,
    'certificate/rsa': True,
    'code/animation/ccb': True,
    'code/autorun': True,
    'code/batch': True,
    'code/c': True,
    'code/csharp': True,
    'code/gles': True,
    'code/glsl': True,
    'code/go': True,
    'code/html': True,
    'code/java': True,
    'code/javascript': True,
    'code/jscript': True,
    'code/ida': True,
    'code/lisp': True,
    'code/pdfjs': True,
    'code/perl': True,
    'code/php': True,
    'code/python': True,
    'code/ruby': True,
    'code/rust': True,
    'code/sgml': True,
    'code/sql': True,
    'code/vbs': True,
    'code/wsf': True,
    'code/xml': True,
    'db/dbf': True,
    'db/sqlite': True,
    'document/installer/windows': True,
    'document/office/excel': True,
    'document/office/powerpoint': True,
    'document/office/rtf': True,
    'document/office/unknown': True,
    'document/office/visio': True,
    'document/office/word': True,
    'document/office/wordpro': True,
    'document/office/wordperfect': True,
    'document/email': True,
    'document/pdf': True,
    'document/unknown': True,
    'executable/unknown': True,
    'executable/windows/com': True,
    'executable/windows/dos': True,
    'executable/windows/pe32': True,
    'executable/windows/pe64': True,
    'executable/windows/dll32': True,
    'executable/windows/dll64': True,
    'executable/linux/elf32': True,
    'executable/linux/elf64': True,
    'executable/linux/so32': True,
    'executable/linux/so64': True,
    'font/texture/pvr': True,
    'image/bmp': True,
    'image/gif': True,
    'image/jpg': True,
    'image/png': True,
    'image/texture/ka3d': True,
    'image/texture/ktx': True,
    'image/texture/pkm': True,
    'image/texture/powervr': True,
    'image/texture/rvio': True,
    'image/unknown': True,
    'java/class': True,
    'java/jar': True,
    'java/java': True,
    'java/jbdiff': True,
    'java/manifest': True,
    'java/signature': True,
    'java/unknown': True,
    'meta/torrent': True,
    'meta/shortcut/windows': True,
    'network/tcpdump': True,
    'network/unknown': True,
    'resource/big': True,
    'resource/ccz': True,
    'resource/cpk': True,
    'resource/dz': True,
    'resource/pak': True,
    'resource/ptc': True,
    'resource/sbm': True,
    'resource/sbr': True,
    'resource/sc': True,
    'resource/unity': True,
    'unknown': True,
}

STANDARD_TAG_CONTEXTS = [
    ('STATIC', 0),
    ('KINETIC', 1),
]

STANDARD_TAG_TYPES = [
    # Assemblyline TAG_TYPES should be numbers between 0 and 9999 (inclusive)

    ('SOURCE', 200),
    ('THREAT_ACTOR', 201),
    ('FILE', 202),

    # FILE specific types

    # PE tags...
    ('PE_LINK_TIME_STAMP', 3),
    ('PE_UNEXPECTED_SECTION_NAME', 4),
    ('PE_PDB_FILENAME', 5),
    ('PE_VERSION_INFO_ORIGINAL_FILENAME', 6),
    ('PE_VERSION_INFO_FILE_DESCRIPTION', 7),
    ('PE_IMPORT_SORTED_SHA1', 8),
    ('PE_RESOURCE_NAME', 9),
    ('PE_EXPORT_FCT_NAME', 10),
    ('PE_EXPORT_MODULE_NAME', 11),
    ('PE_RESOURCE_LANGUAGE', 12),
    ('PE_SECTION_HASH', 13),
    ('PE_IMPORT_MD5', 14),
    ('PE_OEP_BYTES', 15),
    ('PE_OEP_HEXDUMP', 16),

    # NET tags...
    ('NET_IP', 20),
    ('NET_DOMAIN_NAME', 21),
    ('NET_FULL_URI', 22),
    ('NET_NO_DOMAIN_URI', 23),
    ('NET_EMAIL', 24),
    ('NET_EMAIL_DATE', 25),
    ('NET_EMAIL_SUBJECT', 26),
    ('NET_EMAIL_MSG_ID', 27),
    ('NET_PORT', 28),
    # NET - PROTOCOL
    ('NET_ATTRIBUTION', 99),
    ('NET_PROTOCOL', 220),
    ('NET_PROTOCOL_SUSPICIOUS', 221),
    ('NET_ATTACK', 222),
    ('NET_PHONE_NUMBER', 223),

    # Network Signature TAGS
    ('SURICATA_SIGNATURE_ID', 301),
    ('SURICATA_SIGNATURE_MESSAGE', 302),

    # PDF tags...
    ('PDF_DATE_MOD', 30),
    ('PDF_DATE_CREATION', 31),
    ('PDF_DATE_LASTMODIFIED', 32),
    ('PDF_DATE_SOURCEMODIFIED', 33),
    ('PDF_DATE_PDFX', 34),
    ('PDF_STATS_SHA1', 35),
    ('PDF_JAVASCRIPT_SHA1', 36),

    # Search tags...
    ('SEARCH_STRING_CASE_INSENSITIVE', 40),
    ('SEARCH_STRING_CASE_SENSITIVE', 41),
    ('SEARCH_STRING_REGEXP', 42),
    ('SEARCH_BINARY_REGEXP', 43),

    ('MASKING_ALGO', 51),
    ('IMPLANT_STRINGS', 55),
    ('SHELLCODE', 56),

    ('AUTORUN_LOCATION', 52),
    ('BASE64_ALPHABET', 53),
    ('REGISTRY_KEY', 54),

    # AV
    ('AV_VIRUS_NAME', 70),

    # Implant
    ('IMPLANT_NAME', 72),
    ('IMPLANT_FAMILY', 73),

    # OLE
    ('OLE_FIB_TIMESTAMP', 80),

    # Techniques
    ('TECHNIQUE_SHELLCODE', 81),
    ('TECHNIQUE_PACKER', 82),
    ('TECHNIQUE_CRYPTO', 83),
    ('TECHNIQUE_OBFUSCATION', 84),
    ('TECHNIQUE_KEYLOGGER', 85),
    ('TECHNIQUE_COMMS_ROUTINE', 86),
    ('TECHNIQUE_PERSISTENCE', 87),
    ('TECHNIQUE_CONFIG', 88),
    ('TECHNIQUE_MACROS', 89),

    # Info
    ('INFO_COMPILER', 95),
    ('INFO_LIBS', 96),

    # FILE
    ('FILE_SHA1', 0),
    ('FILE_MD5', 1),
    ('FILE_SIZE', 2),

    # This tag is only the file name, no path ... Sometimes, that's all we
    # have. If we want to have a filename with the path context, we'll need
    # another tag.
    ('FILE_NAME', 101),

    ('FILE_ATTRIBUTION', 100),
    ('FILE_STRING', 102),
    ('FILE_MIMETYPE', 103),
    ('FILE_YARA_RULE', 104),
    ('FILE_CONFIG', 105),
    ('FILE_SUMMARY', 106),
    ('FILE_EXTENSION', 107),
    ('FILE_PATH_NAME', 108),
    ('FILE_OBFUSCATION', 109),

    # SERVICE
    ('SERVICE_NAME', 110),
    ('SERVICE_DISPLAY_NAME', 111),
    ('SERVICE_DESCRIPTION', 112),

    # DYNAMIC
    ('DYNAMIC_MUTEX_NAME', 115),
    ('DOS_DEVICE_NAME', 116),
    ('DYNAMIC_PROCESS_FNAME', 117),
    ('DYNAMIC_PROCESS_COMMANDLINE', 118),
    ('DYNAMIC_WINDOW_NAME', 119),
    ('DYNAMIC_WINDOW_CLASSNAME', 120),
    ('DYNAMIC_MALWARE_PATTERN', 121),
    ('DYNAMIC_DROP_PATH', 122),
    ('DYNAMIC_MALICIOUSNESS', 123),
    ('DYNAMIC_CLSIDS_SSDEEP', 124),
    ('DYNAMIC_REGKEYS_SSDEEP', 125),
    ('DYNAMIC_SIGNATURE_CATEGORY', 126),
    ('DYNAMIC_SIGNATURE_NAME', 127),
    ('DYNAMIC_SIGNATURE_FAMILY', 128),

    ('EXPLOIT_NAME', 150),

    # OLE
    ('OLE_CLSID', 160),
    ('OLE_CREATION_TIME', 161),
    ('OLE_LASTMOD_TIME', 162),
    ('OLE_SUMMARY_TITLE', 163),
    ('OLE_SUMMARY_SUBJECT', 164),
    ('OLE_SUMMARY_AUTHOR', 165),
    ('OLE_SUMMARY_COMMENTS', 166),
    ('OLE_SUMMARY_LASTSAVEDBY', 167),
    ('OLE_SUMMARY_LASTPRINTED', 168),
    ('OLE_SUMMARY_CREATETIME', 169),
    ('OLE_SUMMARY_LASTSAVEDTIME', 170),
    ('OLE_SUMMARY_MANAGER', 171),
    ('OLE_SUMMARY_COMPANY', 172),
    ('OLE_SUMMARY_CODEPAGE', 173),
    ('OLE_MACRO_SUSPICIOUS_STRINGS', 174),
    ('OLE_MACRO_SHA256', 175),

    # FILE NAME ANOMALIES
    ('FILENAME_ANOMALIES', 180),

    # SWF TAGS
    ('SWF_TAGS_SSDEEP', 190),

    # ANDROID
    ('ANDROID_PKG_NAME', 200),
    ('ANDROID_MINSDK', 201),
    ('ANDROID_TARGET_SDK', 202),
    ('ANDROID_APP_LABEL', 203),
    ('ANDROID_USE_LIBRARY', 204),
    ('ANDROID_PERMISSION', 205),
    ('ANDROID_ACTIVITY', 206),
    ('ANDROID_FEATURE', 207),
    ('ANDROID_PROVIDES_COMPONENT', 208),
    ('ANDROID_DYNAMIC_CLASSES_SSDEEP', 209),
    ('ANDROID_LOCALE', 210),
    ('ANDROID_CERT_ISSUER', 211),
    ('ANDROID_CERT_OWNER', 212),
    ('ANDROID_CERT_START_DATE', 213),
    ('ANDROID_CERT_END_DATE', 214),


    # HEURISTICS
    ('HEURISTIC', 252),

    # RESERVED FOR SSHTML DISPLAY TYPES
    ('REQUEST_USERNAME', 253),
    ('REQUEST_SCORE', 254),
    ('DISPLAY_STRING_SEARCH', 255),

    # ANALYTIC TAGS
    ('SUSPICIOUS_IMPORTS', 256),
    ('FILE_DECODED_STRING', 257),
    ('FILE_PDB_STRING', 258),
    ('WIN_API_STRING', 259),
    ('PESTUDIO_BLACKLIST_STRING', 260),
    ('TAGCHECK_RULE', 261),
]

SERVICE_STAGES = [
    'SETUP',
    'FILTER',
    'EXTRACT',
    'CORE',
    'SECONDARY',
    'POST',
    'TEARDOWN'
]

SERVICE_CATEGORIES = [
    'Antivirus',
    'Extraction',
    'Filtering',
    'Metadata',
    'Networking',
    'Static Analysis',
    'System',
    'Test'
]

FILE_SUMMARY = []

custom_rules = os.path.join(modulepath(__name__), 'custom.magic')
RULE_PATH = ':'.join((custom_rules, '/usr/share/file/magic.mgc'))
