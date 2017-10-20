import logging
import os
import subprocess 
    
from os import makedirs
from os.path import join as path_join

from assemblyline.al.common import version
from assemblyline.common.logformat import AL_LOG_FORMAT
from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.remote_datatypes import Counters, Hash

config = forge.get_config()
    
#################################################################
# Configuration

CLASSIFICATION = forge.get_classification()

ALLOW_RAW_DOWNLOADS = config.ui.allow_raw_downloads
APP_ID = "https://%s" % config.ui.fqdn
AUDIT = config.ui.audit

SECRET_KEY = config.ui.secret_key
DEBUG = config.ui.debug
PROFILE = config.ui.debug
DOWNLOAD_ENCODING = config.ui.download_encoding
MAX_CLASSIFICATION = CLASSIFICATION.UNRESTRICTED
ORGANISATION = config.system.organisation
SYSTEM_SERVICE_CATEGORY_NAME = config.services.system_category
SYSTEM_NAME = config.system.name

BUILD_MASTER = version.SYSTEM_VERSION
BUILD_LOWER = version.FRAMEWORK_VERSION
BUILD_NO = ""
GIT_PATH = config.ui.install_path

TEMP_DIR_CHUNKED = "/tmp/al_ui/flowjs/chunked/"
TEMP_DIR = "/tmp/al_ui/flowjs/full/"
F_READ_CHUNK_SIZE = 1024 * 1024
TEMP_SUBMIT_DIR = "/tmp/al_ui/submit/"

RATE_LIMITER = Counters(prefix="quota",
                        host=config.core.redis.nonpersistent.host,
                        port=config.core.redis.nonpersistent.port,
                        db=config.core.redis.nonpersistent.db,
                        track_counters=True)

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port,
                  db=config.core.redis.nonpersistent.db)

# End of Configuration
#################################################################

#################################################################
# Audit log

al_log.init_logging("ui")
AUDIT_KW_TARGET = ["sid",
                   "srl",
                   "copy_sid",
                   "filter",
                   "query",
                   "username",
                   "group",
                   "rev",
                   "wq_id",
                   "bucket",
                   "cache_key",
                   "alert_key",
                   "url",
                   "q",
                   "fq",
                   "file_hash",
                   "heuristic_id",
                   "error_key",
                   "mac",
                   "vm_type",
                   "vm_name",
                   "config_name",
                   "profilename",
                   "servicename",
                   "vm"]

# noinspection PyBroadException
try:
    makedirs(config.logging.directory)
except:  # pylint:disable=W0702
    pass


AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui')

if DEBUG:
    AUDIT_LOG.setLevel(logging.DEBUG)
    config.logging.log_to_console = True
    fh = logging.FileHandler(path_join(config.logging.directory, 'alui_audit.log'))
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(AL_LOG_FORMAT))
    AUDIT_LOG.addHandler(fh)
    LOGGER.setLevel(logging.DEBUG)
else:
    AUDIT_LOG.setLevel(logging.INFO)
    LOGGER.setLevel(logging.INFO)

AUDIT_LOG.debug('Audit logger ready!')
LOGGER.debug('Logger ready!')
    
# End of Audit Log
#################################################################

#################################################################
# Find build number
builds = []
for cur_dir in os.listdir(GIT_PATH):
    p = subprocess.Popen(["git", "-C", os.path.join(GIT_PATH, cur_dir), "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, _ = p.communicate()
    # noinspection PyBroadException
    try:
        rev = stdout.splitlines()[0]
        if rev == "HEAD":
            continue

        if cur_dir.startswith("al_"):
            cur_dir = cur_dir[3:]

        builds.append("%s:%s" % (cur_dir[:2], rev[:7]))
    except:  # pylint:disable=W0702
        pass

if len(builds) == 0:
    BUILD_NO = "xxxxxxx"
else:
    BUILD_NO = " - ".join(builds)

# End of Find build number
#################################################################

#################################################################
# Global instances
STORAGE = forge.get_datastore()
YARA_PARSER = forge.get_yara_parser()

dn_parser = forge.get_dn_parser()
# End global
#################################################################


def get_template_prefix(context, name):
    return context['TEMPLATE_PREFIX'].get(name, "")
