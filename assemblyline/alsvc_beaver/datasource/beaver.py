from assemblyline.al.common import forge
from assemblyline.al.datasource.common import Datasource, DatasourceException

import MySQLdb
import MySQLdb.cursors
import traceback
import threading

Classification = forge.get_classification()

callout_query = """\
SELECT
    analyser, callout, mc.port, cast(date(addedDate) as char) as date, channel as request
FROM
    malware_callouts mc
        JOIN
    malware_hash mh USING (md5)
WHERE
    mh.{field} = '{value}' AND
    callout not like '199.16.199%%%%' -- FireEye bogus IP
ORDER BY analyser, callout;
"""

av_hit_query = """\
SELECT
    ar.scannerID, an.name
FROM
    av_results ar
        JOIN
    malware_hash mh USING (md5)
        JOIN
    av_names an USING (nameID)
WHERE
    mh.{field} = '{value}'
GROUP BY scannerID;
"""

source_query = """\
SELECT
    cast(date(min(receivedDate)) as char) as first_seen,
    cast(date(max(receivedDate)) as char) as last_seen,
    count(sourceID) as count,
    filesize as size,
    md5,
    sha1,
    sha256
FROM
    mfs.samples
        JOIN
    malware_hash mh USING (md5)
WHERE
    mh.{field} = '{value}';
"""

upatre_query = """\
SELECT
    h.md5, u.decrypted_md5, u.decryption_key
FROM
    malware_upatre_decrypter u
        join
    malware_hash h ON (h.md5 = u.md5 or h.md5 = u.decrypted_md5)
WHERE
    decrypted_md5 is not null
        and h.{field} = '{value}';
"""

spam_feed_query = """\
SELECT
    cast(date(min(e1.id)) as char) as first_seen,
    cast(date(max(e1.id)) as char) as last_seen,
    e1.filename as attachment,
    e1.md5 as attachment_md5,
    e2.filename,
    e2.md5 as filename_md5,
    count(e1.id) as count
FROM
    malware_hash mh
        JOIN
    efs.samples e1 ON (mh.md5 = e1.md5)
        LEFT JOIN
    efs.samples e2 ON (e2.md5 = e1.parent_md5 OR e2.md5 = e1.parent_md5)
WHERE
    mh.{field} = '{value}'
GROUP BY e1.md5;
"""


class Beaver(Datasource):
    class DatabaseException(Exception):
        pass
    Name = "CCIRC Malware Database"

    def __init__(self, log, **kw):
        super(Beaver, self).__init__(log, **kw)
        self.params = {
            k: kw[k] for k in ('host', 'passwd', 'user')
        }

        self.api_url = None
        self.direct_db = False
        self.session = None

        if 'db' in kw and 'port' in kw:
            self.direct_db = True
            self.params.update({k: kw[k] for k in ('db', 'port')})
        else:
            self.api_url = "%s/al/report/%%s" % kw['host']

        self.tls = threading.local()
        self.tls.connection = None

    def connect(self):
        try:
            self.tls.connection = MySQLdb.connect(
                cursorclass=MySQLdb.cursors.DictCursor,
                connect_timeout=10,
                **self.params
            )
        except MySQLdb.Error:
            self.tls.connection = None
            self.log.warn("Could not connect to database: %s" % traceback.format_exc())
            raise self.DatabaseException()
        except AttributeError:
            self.tls.connection = None
            raise self.DatabaseException("TLS not initialized")

    # noinspection PyUnresolvedReferences
    def _query(self, sql, hash_type, value, fetchall=True):
        results = []

        if not hasattr(self.tls, "connection"):
            self.tls.connection = None

        if self.tls.connection is None:
            self.connect()
        cursor = None
        try:
            cursor = self.tls.connection.cursor()
            cursor.execute(sql.format(field=hash_type, value=value))
            if fetchall:
                results = cursor.fetchall()
            else:
                result = cursor.fetchone()
                if result:
                    results = [result]
            cursor.close()
            cursor = None
        except MySQLdb.Error:
            if cursor is not None:
                try:
                    cursor.close()
                except MySQLdb.ProgrammingError:
                    pass
            try:
                self.tls.connection.close()
            except MySQLdb.Error:
                pass
            self.tls.connection = None
            self.log.warn("Could not query database: %s" % traceback.format_exc())
            raise self.DatabaseException()

        return results

    def parse(self, results, **kw):
        if self.direct_db:
            item = self.parse_db(results)
        else:
            item = self.parse_api(results)

        if item:
            return [item]

        return []

    @staticmethod
    def parse_api(results):
        if not results:
            return []

        malicious = any(results.get(x, None) for x in (
            'av_results', 'callouts', 'spamCount',
        ))

        rdate = results['received_date']

        first_seen = "%s-%s-%sT00:00:00Z" % (
            rdate[:4], rdate[4:6], rdate[6:]
        )

        hash_info = results['hash_info']

        data = {
            "first_seen": first_seen,
            "last_seen": first_seen,  # No last_seen is provided.
            "md5": hash_info.get('md5', ""),
            "sha1": hash_info.get('sha1', ""),
            "sha256": hash_info.get('sha256', ""),
            "size": hash_info.get('filesize', ""),
        }
        data.update(results)

        return {
            "confirmed": malicious,
            "data": data,
            "description": "File found in the %s." % Beaver.Name,
            "malicious": malicious,
        }

    @staticmethod
    def parse_db(results):
        data = results.pop('source', {})
        count = data.get('count', 0)
        if not count:
            return []

        malicious = any(results.get(x, None) for x in (
            'antivirus', 'callout', 'spam_feed', 'upatre',
        ))

        data.update(results)

        return {
            "confirmed": malicious,
            "data": data,
            "description": "File found %s time(s) in the %s." % (count, Beaver.Name),
            "malicious": malicious,
        }

    def query_api(self, hash_type, value):
        if hash_type != "md5":
            raise DatasourceException("%s API only supports MD5" % self.Name)

        if self.session is None:
            # noinspection PyUnresolvedReferences
            import requests
            self.session = requests.Session()

        response = self.session.get(
            self.api_url % value,
            auth=(self.params['user'], self.params['passwd'])
        )

        # noinspection PyBroadException
        try:
            response.raise_for_status()  # Raise exception when status_code != 200.
        except:
            error = response.json()
            error_code = error.get('error_code', str(response.status_code))
            if int(error_code) == 105:  # File not found error code
                return {}
            else:
                raise Exception("[%s] %s" % (error_code, error.get("error_message", "Unknown error")))

        return response.json()

    def query_db(self, hash_type, value):
        results = {}

        result = self._query(source_query, hash_type, value, fetchall=False)
        if not result:
            return results

        results['source'] = result[0]

        results['antivirus'] = self._query(av_hit_query, hash_type, value)
        results['callout'] = self._query(callout_query, hash_type, value)
        results['spam_feed'] = self._query(spam_feed_query, hash_type, value, fetchall=False)
        results['upatre'] = self._query(upatre_query, hash_type, value, fetchall=False)

        return results

    def query(self, value, **kw):
        hash_type = self.hash_type(value)
        value = value.lower()

        if self.direct_db:
            return self.query_db(hash_type, value)
        else:
            return self.query_api(hash_type, value)
