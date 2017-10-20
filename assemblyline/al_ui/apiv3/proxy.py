# coding:utf-8
# Copyright 2011 litl, LLC. All Rights Reserved.

import httplib
import re

from al_ui.config import config

from base64 import b64encode
from flask import abort, Blueprint, request, Response, url_for
from werkzeug.datastructures import Headers

from al_ui.helper.views import protected_renderer

proxy = Blueprint('proxy', __name__)

HTML_REGEX = re.compile(r'((?:src|action|href)=["\'])/')
JQUERY_REGEX = re.compile(r'(\$\.(?:get|post)\(["\'])/')
JS_LOCATION_REGEX = re.compile(r'((?:window|document)\.location.*=.*["\'])/')
CSS_REGEX = re.compile(r'(url\(["\']?)/')
KIBANA_REGEX = re.compile(r'(setAttribute\(\'href\', ")/')
KIBANA_REGEX_2 = re.compile(r'(Route = \')/')
KIBANA_REGEX_3 = re.compile(r'("url":")/')
KIBANA_REGEX_4 = re.compile(r'("main":")')
KIBANA_REGEX_5 = re.compile(r'(__webpack_require__.p = ")/')
KIBANA_REGEX_6 = re.compile(r'(addBasePath\(\')/')

REGEXES = [
    HTML_REGEX,
    JQUERY_REGEX,
    JS_LOCATION_REGEX,
    CSS_REGEX,
    KIBANA_REGEX,
    KIBANA_REGEX_2,
    KIBANA_REGEX_3,
    KIBANA_REGEX_4,
    KIBANA_REGEX_5,
    KIBANA_REGEX_6
]


@proxy.route('/kibana-proxy/', methods=["GET", "POST"])
@proxy.route('/kibana-proxy/<path:requested_file>', methods=["GET", "POST"])
@protected_renderer(audit=False, require_admin=True)
def proxy_request(requested_file="", **_):
    if not requested_file.startswith("app/kibana") and not requested_file.startswith("bundles/") and \
            not requested_file.startswith("elasticsearch/"):
        abort(403)

    hostname = config.logging.logserver.kibana.host
    port = config.logging.logserver.kibana.port
    scheme = config.logging.logserver.kibana.scheme
    password = config.logging.logserver.kibana.password
    auth = b64encode("kibanaadmin:%s" % password)

    # Whitelist a few headers to pass on
    request_headers = {
        'Authorization': 'Basic %s' % auth
    }
    for h in ["Referer", "X-Csrf-Token", "kbn-version"]:
        if h in request.headers:
            request_headers[h] = request.headers[h]

    if request.query_string:
        path = "/%s?%s" % (requested_file, request.query_string)
    else:
        path = "/" + requested_file

    if request.method == "POST":
        form_data = request.data
        request_headers["Content-Length"] = len(form_data)
    else:
        form_data = None

    if scheme == "http":
        conn = httplib.HTTPConnection(hostname, port)
        conn.request(request.method, path, body=form_data, headers=request_headers)
        resp = conn.getresponse()
    else:
        conn = httplib.HTTPSConnection(hostname, port)
        conn.request(request.method, path, body=form_data, headers=request_headers)
        resp = conn.getresponse()

    # Clean up response headers for forwarding
    response_headers = Headers()
    for key, value in resp.getheaders():
        if key in ["content-length", "connection", "content-type"]:
            continue

        if key == "set-cookie":
            cookies = value.split(",")
            [response_headers.add(key, c) for c in cookies]
        else:
            response_headers.add(key, value)

    # Rewrite URLs in the content to point to our URL scheme instead.
    # Ugly, but seems to mostly work.
    root = url_for(".proxy_request")
    contents = resp.read()
    for regex in REGEXES:
        contents = regex.sub(r'\1%s' % root, contents)

    flask_response = Response(response=contents,
                              status=resp.status,
                              headers=response_headers,
                              content_type=resp.getheader('content-type'))
    return flask_response
