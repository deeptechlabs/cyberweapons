from assemblyline.al.common import forge
from assemblyline.al.datasource.common import Datasource, DatasourceException

import psycopg2
import traceback
import threading

Classification = forge.get_classification()

Query = """\
select name, product, os, version, manufacturer, language
from nsrl
where {field} = '{value}'{limit};
"""

class NSRL(Datasource):
    class DatabaseException(Exception):
        pass
    Name = "NSRL"

    def __init__(self, log, **kw):
        super(NSRL, self).__init__(log, **kw)
        self.params = {
            'dbname': kw['db'],
            'host': kw['host'],
            'password': kw['passwd'],
            'port': kw['port'],
            'user': kw['user'],
        }
        self.tls = threading.local()
        self.tls.connection = None

    def connect(self):
        try:
            self.tls.connection = psycopg2.connect(connect_timeout=10, **self.params)
        except psycopg2.Error:
            self.tls.connection = None
            self.log.warn("Could not connect to database: %s" % traceback.format_exc())
            raise self.DatabaseException()
        except AttributeError:
            self.tls.connection = None
            raise self.DatabaseException("TLS not initialized")

    def parse(self, results, **kw):
        items = []
        for result in results:
            (name, product, os, version, manufacturer, language) = result
            items.append({
                'confirmed': True,
                'data': {
                    'filename': name,
                    'language': language,
                    'mfgcode': manufacturer,
                    'opsystemcode': os,
                    'productname': product,
                    'productversion': version,
                },
                'description': "%s - %s (%s) - v: %s - by: %s [%s]" % result,
                'malicious': False,
            })
        return items

    def query(self, value, **kw):
        hash_type = self.hash_type(value)
        if hash_type == "sha256":
            raise DatasourceException("%s does not support SHA256" % self.Name)

        results = []

        limit = kw.get('limit', '')
        if limit:
            limit = " limit " + str(limit)

        if not hasattr(self.tls, "connection"):
            self.tls.connection = None
            
        if self.tls.connection is None:
            self.connect()

        try:
            with self.tls.connection.cursor() as cursor:
                query = Query.format(
                    field=hash_type, limit=limit, value=value.upper()
                )
                cursor.execute(query)
                results = cursor.fetchall()
        except psycopg2.Error:
            try:
                self.tls.connection.close()
            except psycopg2.Error:
                pass
            self.tls.connection = None
            self.log.warn("Could not query database: %s" % traceback.format_exc())
            raise self.DatabaseException()

        return results

