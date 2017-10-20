from assemblyline.al.common import forge
from assemblyline.al.datasource.common import Datasource

import MySQLdb
import MySQLdb.cursors
import traceback
import threading

Classification = forge.get_classification()

Query = """\
select  md5, sha1, sha256, size, filename
from cfmd_hashes
where {field} = '{value}'{limit};
"""

class CFMD(Datasource):
    class DatabaseException(Exception):
        pass

    Name = "Microsoft Clean File Metadata Database"

    def __init__(self, log, **kw):
        super(CFMD, self).__init__(log, **kw)
        self.params = {
            k: kw[k] for k in ('db', 'host', 'passwd', 'port', 'user')
        }
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

    def parse(self, results, **kw):
        if len(results) <= 0:
            return []

        result = results[0]

        result['filenames'] = list(set([x['filename'] for x in results]))

        result.pop('filename', None)

        return [{
                'confirmed': True,
                'data': result,
                'description': "File found %s time(s) in the %s." % (
                    len(result['filenames']), self.Name
                ),
                'malicious': False,
        }]

    def query(self, value, **kw):
        hash_type = self.hash_type(value)

        results = []

        limit = kw.get('limit', '')
        if limit:
            limit = " limit " + str(limit)

        if not hasattr(self.tls, "connection"):
            self.tls.connection = None

        if self.tls.connection is None:
            self.connect()
        cursor = None
        try:
            query = Query.format(
                field=hash_type, limit=limit, value=value.upper()
            )
            cursor = self.tls.connection.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
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

