import logging
import logging.handlers
import logging.config
import os

from assemblyline.common.logformat import AL_LOG_FORMAT, AL_SYSLOG_FORMAT
from assemblyline.al.common import forge


def init_logging(name='al'):
    config = forge.get_config()
    logging.root.setLevel(logging.CRITICAL)
    logger = logging.getLogger('assemblyline')
    logger.setLevel(logging.INFO)

    if config.logging.log_to_file:
        if not os.path.isdir(config.logging.directory):
            print 'Warning: log directory does not exist. Will try to create %s' % config.logging.directory
            os.makedirs(config.logging.directory)

        op_file_handler = logging.handlers.RotatingFileHandler(os.path.join(config.logging.directory, name + '.log'),
                                                               maxBytes=10485760, backupCount=5)
        op_file_handler.setLevel(logging.INFO)
        op_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(op_file_handler)

        err_file_handler = logging.handlers.RotatingFileHandler(os.path.join(config.logging.directory, name + '.err'),
                                                                maxBytes=10485760, backupCount=5)
        err_file_handler.setLevel(logging.ERROR)
        err_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(err_file_handler)
 
    if config.logging.log_to_console:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(console)

    if config.logging.log_to_syslog and config.logging.syslog_ip:
        syslog_handler = logging.handlers.SysLogHandler(address=(config.logging.syslog_ip, 514))
        syslog_handler.formatter = logging.Formatter(AL_SYSLOG_FORMAT)
        logger.addHandler(syslog_handler)
