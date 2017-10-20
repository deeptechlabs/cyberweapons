from assemblyline.al.common import forge
from assemblyline.al.datasource.common import Datasource

Classification = forge.get_classification()

class Alert(Datasource):
    def __init__(self, log, **kw):
        super(Alert, self).__init__(log, **kw)
        self.datastore = forge.get_datastore()

    def parse(self, results, **kw):
        return results

    def query(self, value, **kw):
        hash_type = self.hash_type(value)

        query = "%s:%s OR %s:%s" % (
            hash_type, value.lower(), hash_type, value.upper()
        )

        res = self.datastore.direct_search(
            "alert", query, [("rows", "5"), ("sort", "al_score desc")],
            __access_control__=kw['access_control']
        ).get("response", {})

        count = res.get('numFound', 0)
        if count <= 0:
            return []

        data = []
        item = {
            "confirmed": False,
            "data": data,
            "description": "Alerted on %s times" % str(count),
            "malicious": False,
        }

        for r in res.get('docs', []):
            score = r['al_score']
            if score >= 500:
                item['malicious'] = True    
            if score >= 2000 or score <= -100:
                item['confirmed'] = True

            data.append({
                "classification": r['classification'],
                "date": r['reporting_ts'],
                "event_id": r['event_id'],
                "score": r['al_score'],
            })

        return [item]

