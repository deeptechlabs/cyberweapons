from __future__ import absolute_import

import os
import time

from assemblyline.al.service.base import ServiceBase

NEAR = 0
COUNT_PUTS = 'svc.sync.puts'
COUNT_DOWNLOADS = 'svc.sync.downloads'

class Sync(ServiceBase):

    SERVICE_CATEGORY = "System"
    SERVICE_DISABLE_CACHE = True
    SERVICE_DESCRIPTION = "This service is responsible for syncing files across the system's multi-level storage. " \
                          "As a SYSTEM service, this service is always executed and cannot be unselected."
    SERVICE_ENABLED = True
    SERVICE_SAVE_RESULT = False
    SERVICE_STAGE = "SETUP"
    SERVICE_TIMEOUT = 30
    SERVICE_CPU_CORES = 0.2
    SERVICE_RAM_MB = 32

    def __init__(self, cfg=None):
        super(Sync, self).__init__(cfg)

    def execute(self, request):
        start_t = time.time()
        exists = self.transport.exists(request.srl, location='all')
        check_t = time.time()

        makedir_t = download_t = put_t = remove_t = check_t

        needed = list(set(self.transport.transports).difference(set(exists)))
        if exists and needed:
            local = request.tempfile(request.srl)
            makedir_t = time.time()

            exists[NEAR].download(request.srl, local)
            self.counters[COUNT_DOWNLOADS] += 1
            download_t = time.time()

            for t in needed:
                self.counters[COUNT_PUTS] += 1
                t.put(local, request.srl)

            put_t = time.time()

            os.remove(local)
            remove_t = time.time()

        self.log.info(
            "Sync completed: c:%.3f m:%.3f d:%.3f p:%.3f r:%.3f %s %s => %s",
            check_t - start_t, makedir_t - check_t, download_t - makedir_t,
            put_t - download_t, remove_t - put_t, request.srl,
            [t.host for t in exists], [t.host for t in needed],
        )
