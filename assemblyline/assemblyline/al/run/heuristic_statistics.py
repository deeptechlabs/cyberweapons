#!/usr/bin/env python

import logging

from assemblyline.common.isotime import now_as_local
from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.heuristics import list_all_heuristics
config = forge.get_config()

al_log.init_logging('heuristic_statistics')
log = logging.getLogger('assemblyline.heuristic_statistics')

log.info("Generating heuristic statistics")
store = forge.get_datastore()

output = {"timestamp": None, "stats": None}
stats = {}

HEUR, _ = list_all_heuristics(store.list_services())

for heur in HEUR:
    heur_key = heur["id"]
    results = store.stats_search("result", query='result.tags.value:"%s"' % heur["id"],
                                 stats_fields=["result.score"])["result.score"]

    if results:
        heur_stat = [results["count"], results["min"], int(results["mean"]), results["max"]]
        log.info("%s => %s" % (heur_key, heur_stat))
    else:
        heur_stat = None
        log.debug("Heuristic %s has never hit" % heur_key)

    if heur_stat:
        stats[heur_key] = heur_stat

output["stats"] = stats
output["timestamp"] = str(now_as_local())[0:16]

store.save_blob("heuristics_stats", output)
log.info("Heuristic statistics generation completed")
