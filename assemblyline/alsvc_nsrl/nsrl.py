#!/usr/bin/env python

""" NSRL hash lookup service.  """
from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.service.base import ServiceBase
from assemblyline.common.exceptions import RecoverableError


class NSRL(ServiceBase):
    """ NSRL (Checks a list of known good files using SHA1 and size). """

    SERVICE_CATEGORY = "Filtering"
    SERVICE_DEFAULT_CONFIG = {
        "host": "127.0.0.1",
        "user": "guest",
        "passwd": "guest",
        "port": 5432,
        "db": "nsrl"
    }
    SERVICE_DESCRIPTION = "This service performs hash lookups against the NSRL database of known good files."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = 'FILTER'
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.05
    SERVICE_RAM_MB = 64

    def __init__(self, cfg=None):
        super(NSRL, self).__init__(cfg)
        self._connect_params = {
            'host': self.cfg.get('host'),
            'user': self.cfg.get('user'),
            'port': int(self.cfg.get('port')),
            'passwd': self.cfg.get('passwd'),
            'db': self.cfg.get('db')
        }
        self.connection = None

    def start(self):
        self.connection = NSRLDatasource(self.log, **self._connect_params)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global NSRLDatasource
        from al_services.alsvc_nsrl.datasource.nsrl import NSRL as NSRLDatasource

    def execute(self, request):
        # We have the sha1 digest in the task object so there is no need to
        # fetch the sample for NSRL execution. 
        cur_result = Result()
        try:
            dbresults = self.connection.query(request.sha1)
        except NSRLDatasource.DatabaseException:
            raise RecoverableError("Query failed")

        # If we found a result in the NSRL database, drop this task as we don't want to process it further.
        if dbresults:
            request.drop()            
            benign = "This file was found in the NSRL database. It is not malware."
            res = ResultSection(title_text=benign)
            res.score = SCORE.NOT
            for dbresult in dbresults[:10]:    
                res.add_line(dbresult[0] + " - %s (%s) - v: %s - by: %s [%s]"
                             % (dbresult[1], dbresult[2], dbresult[3],
                                dbresult[4], dbresult[5]))

            if len(dbresults) > 10:
                res.add_line("And %s more..." % str(len(dbresults) - 10))

            cur_result.add_section(res)
        request.result = cur_result


if __name__ == '__main__':
    import pprint
    import sys

    nsrl = NSRL()
    if len(sys.argv) != 2:
        print "Usage: %s <SHA1>" % sys.argv[0]
        exit(1)

    SHA1LEN = 40
    value = sys.argv[1].strip().upper()
    if len(value) != SHA1LEN:
        print "Invalid SHA1. Should be %s chars. Actual: %s : %s" % (
            SHA1LEN, len(value), sys.argv[1]
        )
        exit(1)

    result = nsrl.lookup(value)
    if not result:
        print 'Not Found: %s' % value
        exit(0)

    pprint.pprint(result)
