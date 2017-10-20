from assemblyline.al.common import forge
from assemblyline.al.datasource.common import Datasource

Classification = forge.get_classification()


class AL(Datasource):
    def __init__(self, log, **kw):
        super(AL, self).__init__(log, **kw)
        self.datastore = forge.get_datastore()

    def parse(self, results, **kw):
        return results

    def query(self, value, **kw):
        results = []

        hash_type = self.hash_type(value)

        query = "%s:%s OR %s:%s" % (
            hash_type, value.lower(), hash_type, value.upper()
        )

        res = self.datastore.direct_search(
            "file", query, [("rows", "5")],
            __access_control__=kw['access_control']
        )

        for r in res.get("response", {}).get("docs", []):
            args = [
                ("fl", "result.score,_yz_rk"),
                ("group", "on"),
                ("group.field", "response.service_name"),
                ("group.format", "simple"),
                ("rows", "100"),
                ("sort", "created desc"),
            ]

            score = 0
            score_map = {}

            res = self.datastore.direct_search(
                "result", "_yz_rk:%s*" % r['sha256'], args,
                 __access_control__=kw["access_control"]
            )

            for d in res['grouped']['response.service_name']['doclist']['docs']:
                service_name = d['_yz_rk'][65:].split(".", 1)[0]
                if service_name != "HashSearch":
                    score_map[service_name] = d['result.score']
                    score += d['result.score']

            result = {
                "classification": r['classification'],
                "confirmed": score >= 2000 or score < -499,
                "data" : {
                    "classification": r['classification'],
                    "md5": r['md5'],
                    "sha1": r['sha1'],
                    "sha256": r['sha256'],
                    "size": r['size'],
                    "tag": r['tag'],
                    "seen_count": r['seen_count'],
                    "seen_last": r['seen_last'],
                    "score": score,
                    "score_map": score_map
                },
                "description": "File found in AL with score of %s." % score,
                "malicious": score >= 1000,
            }

            results.append(result)

        return results

