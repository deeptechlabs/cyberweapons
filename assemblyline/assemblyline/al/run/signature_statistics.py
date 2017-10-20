#!/usr/bin/env python

import logging

from assemblyline.common.isotime import now_as_local
from assemblyline.al.common import forge, log as al_log

config = forge.get_config()
Classification = forge.get_classification()

al_log.init_logging('signature_statistics')
log = logging.getLogger('assemblyline.signature_statistics')

log.info("Generating signature statistics")
store = forge.get_datastore()

output = {"timestamp": None, "stats": None}
stats = {}

sig_list = [(x['meta.id'], x['meta.rule_version'], x['name'],
             x.get('meta.classification', Classification.UNRESTRICTED)) for x in
            store.stream_search("signature", "name:*", fl="name,meta.id,meta.rule_version,meta.classification")]

for sid, rev, name, classification in sig_list:
    key = "%sr.%s" % (sid, rev)
    res = store.stats_search("result", query='result.tags.value:"%s"' % name,
                             stats_fields=["result.score"])["result.score"]

    if res:
        sig_stat = [name, classification, res["count"], res["min"], int(res["mean"]), res["max"]]
        log.info("%s => %s" % (key, sig_stat))
    else:
        sig_stat = None
        log.debug("Signature %sr.%s has never hit" % (sid, rev))

    if sig_stat:
        stats[key] = sig_stat

output["stats"] = stats
output["timestamp"] = str(now_as_local())[0:16]

store.save_blob("signature_stats", output)
log.info("Signature statistics generation completed")
