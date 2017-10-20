#!/usr/bin/env python

from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.service.base import Category, ServiceBase, Stage
from assemblyline.common.exceptions import RecoverableError

CFMDDatasource = None

class CFMD(ServiceBase):
    SERVICE_ACCEPTS = '.*'
    SERVICE_ENABLED = True
    SERVICE_CATEGORY = Category.FILTERING
    SERVICE_STAGE = Stage.FILTER
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_DEFAULT_CONFIG = {
        "host": "127.0.0.1",
        "user": "cfmd",
        "passwd": "password",
        "port": 3306,
        "db": "cfmd"
    }
    SERVICE_DESCRIPTION = "Performs hash lookups against Microsoft's CleanFileMetaData database."
    SERVICE_CPU_CORES = 0.05
    SERVICE_RAM_MB = 64

    def __init__(self, cfg=None):
        super(CFMD, self).__init__(cfg)

        self._connect_params = {
            'host': self.cfg.get('host'),
            'user': self.cfg.get('user'),
            'port': int(self.cfg.get('port')),
            'passwd': self.cfg.get('passwd'),
            'db': self.cfg.get('db')
        }
        self.connection = None

    def start(self):
        self.connection = CFMDDatasource(self.log, **self._connect_params)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global CFMDDatasource
        from al_services.alsvc_cfmd.datasource.cfmd import CFMD as CFMDDatasource

    def execute(self, request):
        result = Result()

        try:
            res = self.connection.query(request.sha256)
        except CFMDDatasource.DatabaseException:
            raise RecoverableError("Query failed")
        if res:
            res_sec = ResultSection(
                title_text="This file was found in the %s. It is not malware." % CFMDDatasource.Name,
                score=SCORE['NOT'])

            for item in res:
                res_sec.add_line("%s (%s bytes)" % (
                    item['filename'], item['size']
                ))
                res_sec.add_line(" MD5: %s" % item['md5'])
                res_sec.add_line(" SHA1: %s" % item['sha1'])
                res_sec.add_line(" SHA256: %s" % item['sha256'])
                res_sec.add_line("")

            result.add_section(res_sec)

        request.result = result
