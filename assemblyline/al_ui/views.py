import codecs
import fnmatch
import json
import markdown
import os
import re

from collections import OrderedDict
from flask import Blueprint, render_template, request, abort, redirect, Markup

from assemblyline.al.common.security import generate_async_keys
from assemblyline.common.isotime import iso_to_local
from assemblyline.al.common import forge
from al_ui.config import STORAGE, ORGANISATION
from al_ui.helper.views import protected_renderer, custom_render, crossdomain, redirect_helper, angular_safe

config = forge.get_config()

context = forge.get_ui_context()
Classification = forge.get_classification()

views = Blueprint("views", __name__, template_folder="templates")


######################################
# All users pages
@views.route("/account.html")
@protected_renderer(audit=False)
def account(**kwargs):
    return custom_render("account.html", **kwargs)


# noinspection PyBroadException
@views.route("/alerts.html")
@protected_renderer(audit=False)
def alerts(*_, **kwargs):
    filtering_group_fields = config.core.alerter.filtering_group_fields
    non_filtering_group_fields = config.core.alerter.non_filtering_group_fields
    possible_group_fields = filtering_group_fields + non_filtering_group_fields

    search_filter = angular_safe(request.args.get("filter", "*"))
    if search_filter:
        search_filter = search_filter.replace("\\", "\\\\")
        search_filter = search_filter.replace("'", "\\'")

    search_text = search_filter
    if search_filter == "":
        search_filter = "*"
    elif search_filter == "*":
        search_text = ""

    filter_queries = [angular_safe(x) for x in request.args.getlist("fq") if x != ""]

    time_slice = angular_safe(request.args.get("time_slice", "4DAY"))
    start_time = angular_safe(request.args.get("start_time", None))
    view_type = angular_safe(request.args.get("view_type", "grouped"))
    group_by = angular_safe(request.args.get("group_by", config.core.alerter.default_group_field))
    if group_by not in possible_group_fields:
        group_by = config.core.alerter.default_group_field
    temp = time_slice.replace("HOUR", "").replace("MINUTE", "").replace("DAY", "").replace("WEEK", "")\
        .replace("YEAR", "")

    if time_slice != "":
        try:
            int(temp)
        except Exception:
            time_slice = "4DAY"

    return custom_render("alerts.html",
                         search_text=search_text,
                         filter=search_filter,
                         start_time=start_time,
                         time_slice=time_slice,
                         view_type=view_type,
                         filter_queries=json.dumps(filter_queries),
                         group_by=group_by,
                         filtering_group_fields=json.dumps(filtering_group_fields),
                         non_filtering_group_fields=json.dumps(non_filtering_group_fields),
                         **kwargs)


@views.route("/alert_detail.html")
@protected_renderer(audit=False)
def alert_detail(*_, **kwargs):
    user = kwargs['user']

    alert_key = angular_safe(request.args.get("alert_key", None))
    if not alert_key:
        abort(404)

    alert = STORAGE.get_alert(alert_key)
    if user and alert and Classification.is_accessible(user['classification'], alert['classification']):
        return custom_render("alert_detail.html", alert_key=alert_key, **kwargs)
    else:
        abort(403)


@views.route("/api_doc.html")
@protected_renderer(audit=False)
def api_doc(**kwargs):
    return custom_render("api_doc.html", **kwargs)


@views.route("/classification_help.html")
@protected_renderer(audit=False)
def classification_help(*_, **kwargs):
    return custom_render("classification_help.html", **kwargs)


@views.route("/configuration.html")
@protected_renderer(audit=False)
def configuration(**kwargs):
    return custom_render("configuration.html", **kwargs)


@views.route("/dashboard.html")
@protected_renderer(audit=False)
def dashboard(**kwargs):
    return custom_render("dashboard.html", **kwargs)


@views.route("/")
@protected_renderer(audit=False)
def default(**kwargs):
    return submit(**kwargs)


@views.route("/file_detail.html", methods=["GET"])
@protected_renderer(load_options=True, audit=False)
def file_detail(**kwargs):
    user = kwargs['user']
    srl = angular_safe(request.args.get("srl", None))
    
    if not srl:
        abort(404)

    data = STORAGE.get_file(srl)
    
    if not data:
        abort(404)
    
    if not Classification.is_accessible(user['classification'], data['classification']):
        abort(403)
    
    return custom_render("file_detail.html", srl=srl, **kwargs)


@views.route("/file_viewer.html")
@protected_renderer(audit=False)
def file_viewer(**kwargs):
    user = kwargs['user']
    srl = angular_safe(request.args.get("srl", None))
    
    if not srl:
        abort(404)
    
    data = STORAGE.get_file(srl)
    
    if not data:
        abort(404)
    
    if not Classification.is_accessible(user['classification'], data['classification']):
        abort(403)
    
    return custom_render("file_viewer.html", srl=srl, **kwargs)


# Site-Specific heuristics page
@views.route("/heuristics.html")
@protected_renderer(audit=False)
def heuristics(*_, **kwargs):
    return custom_render("heuristics.html", **kwargs)


@views.route("/heuristics_stats.html")
@protected_renderer(audit=False)
def heuristics_stats(*_, **kwargs):
    return custom_render("heuristics_stats.html", **kwargs)


@views.route("/kibana-dash.html")
@protected_renderer(audit=False, require_admin=True)
def kibana_dashboard(**kwargs):
    dash = angular_safe(request.args.get('dash', None))
    if not dash:
        abort(404)

    return custom_render("kibana-dash.html", dash=dash,
                         padding={True: 70, False: 50}[kwargs['user']['c12n_enforcing']], **kwargs)


@views.route("/login.html")
def login():
    if request.environ.get("HTTP_X_REMOTE_CERT_VERIFIED", "FAILURE") == "SUCCESS":
        dn = ",".join(request.environ.get("HTTP_X_REMOTE_DN").split("/")[::-1][:-1])
    else:
        dn = ""

    avatar = None
    username = ''
    alternate_login = 'true'
    if dn:
        u_list = STORAGE.advanced_search('user', 'dn:"%s"' % dn, args=[('fl', '_yz_rk')])['response']['docs']
        if len(u_list):
            username = u_list[0]['_yz_rk']
            avatar = STORAGE.get_user_avatar(username) or "/static/images/user_default.png"
            alternate_login = 'false'
        else:
            try:
                username = dn.rsplit('CN=', 1)[1]
            except IndexError:
                username = dn
            avatar = "/static/images/user_default.png"
            alternate_login = 'false'

    if config.auth.get('encrypted_login', True):
        public_key = STORAGE.get_blob('id_rsa.pub')
        if not public_key:
            public_key, private_key = generate_async_keys(key_size=config.ui.get('rsa_key_size', 2048))
            STORAGE.save_blob('id_rsa.pub', public_key)
            STORAGE.save_blob('id_rsa', private_key)
    else:
        public_key = None

    next_url = angular_safe(request.args.get('next', "/"))
    return custom_render("login.html", next=next_url, public_key=public_key, avatar=avatar,
                         username=username, alternate_login=alternate_login)


@views.route("/logout.html")
@protected_renderer(load_options=False, audit=False)
def logout(**_):
    return custom_render("logout.html",)


@views.route("/search.html")
@protected_renderer(load_options=True, audit=False)
def search(**kwargs):
    query = angular_safe(request.args.get('query', None))
    if query:
        query = query.replace("\\", "\\\\")
        query = query.replace("'", "\\'")
    return custom_render("search.html", query=query, **kwargs)


@views.route("/search_help.html")
@protected_renderer(audit=False)
def search_help(**kwargs):
    field_list = {k: sorted([(x, y) for x, y in v.iteritems()])
                  for k, v in STORAGE.generate_field_list(False).iteritems()}
    lookup = {
        "text_ws": "whitespace separated text",
        "text_ws_dsplit": "dot and whitespace separated text",
        "text_general": "tokenized text",
        "text_fuzzy": "separated fuzzy patterns",
    }
    return custom_render("search_help.html", field_list=field_list, lookup=lookup, **kwargs)


@views.route("/services.html")
@protected_renderer(audit=False)
def services(**kwargs):
    return custom_render("services.html", **kwargs)


@views.route("/settings.html")
@protected_renderer(audit=False)
def settings(**kwargs):
    forced = 'forced' in request.args
    if forced:
        forced = 'true'
    else:
        forced = 'false'
    return custom_render("settings.html", forced=forced, **kwargs)


@views.route("/signature_detail.html", methods=["GET"])
@protected_renderer(load_options=True, audit=False)
def signature_detail(**kwargs):
    user = kwargs['user']
    sid = angular_safe(request.args.get("sid", None))
    rev = angular_safe(request.args.get("rev", None))
    
    if not sid or not rev:
        abort(404)
    
    data = STORAGE.get_signature("%sr.%s" % (sid, rev))

    if not data:
        abort(404)
        
    if not Classification.is_accessible(user['classification'],
                                        data['meta'].get('classification', Classification.UNRESTRICTED)):
        abort(403)

    return custom_render("signature_detail.html",
                         sid=sid,
                         rev=rev,
                         organisation=ORGANISATION,
                         **kwargs)


@views.route("/signatures.html")
@protected_renderer(audit=False)
def signatures(**kwargs):
    return custom_render("signatures.html", org=ORGANISATION, **kwargs)


@views.route("/signature_statistics.html")
@protected_renderer(audit=False)
def signature_statistics(*_, **kwargs):
    return custom_render("signature_statistics.html", **kwargs)


@views.route("/submission_detail.html", methods=["GET"])
@protected_renderer(load_options=True)
def submission_detail(**kwargs):
    sid = angular_safe(request.args.get("sid", None))
    new = "new" in request.args
    if new:
        new = 'true'
    else:
        new = 'false'
    return custom_render("submission_detail.html", sid=sid, new=new, **kwargs)


@views.route("/submissions.html")
@protected_renderer(audit=False)
def submissions(**kwargs):
    user = kwargs['user']
    
    group = angular_safe(request.args.get('group', None))
    uname = None 
        
    if not group:
        uname = angular_safe(request.args.get('user', user['uname']))

    return custom_render("submissions.html", uname=uname, group=group, **kwargs)


@views.route("/submit.html")
@protected_renderer(audit=False)
def submit(**kwargs):
    show_tos = config.ui.get("tos", None) is not None
    return custom_render("submit.html", show_tos=show_tos, **kwargs)


@views.route("/terms.html")
@protected_renderer(audit=False)
def tos(**kwargs):
    if config.ui.get("tos", None) is not None:
        kwargs['menu'] = None
        agreed_date = kwargs['user'].get('agrees_with_tos', None)
        if agreed_date:
            agreed_date = iso_to_local(agreed_date)[:19]
        tos_raw = Markup(markdown.markdown(config.ui.tos))
        return custom_render("terms.html", tos=tos_raw, agreed_date=agreed_date, **kwargs)
    else:
        return redirect(redirect_helper("/"))


@views.route("/unsupported.html")
def unsupported():
    return render_template("unsupported.html", user_agent=request.environ["HTTP_USER_AGENT"],
                           is_ie=("MSIE" in request.environ["HTTP_USER_AGENT"]))


@views.route("/yara_standard.html")
@protected_renderer(audit=False)
def yara_help(**kwargs):
    return custom_render("yara_standard.html", **kwargs)


@views.route("/workflows.html")
@protected_renderer(audit=False)
def workflows(**kwargs):
    return custom_render("workflows.html", **kwargs)


############################################
# Admin Protected pages
@views.route("/admin/documentation.html")
@protected_renderer(require_admin=True, audit=False)
def admin_build_doc(**kwargs):
    def _list_files():
        fmap = OrderedDict()
        flist = []
        for root, dirnames, filenames in os.walk(config.ui.install_path):
            for filename in fnmatch.filter(filenames, '*.md'):
                file_path = os.path.join(root, filename)
                file_path = file_path.replace(config.ui.install_path, "")
                if file_path.startswith("/"):
                    file_path = file_path[1:]

                flist.append(file_path)

                pkg_root, fname = file_path.replace("/opt/al/pkg/", "").split(os.sep, 1)

                if pkg_root not in fmap:
                    fmap[pkg_root] = []

                fmap[pkg_root].append(fname)

        for key in fmap.keys():
            fmap[key] = sorted(fmap[key])

        return fmap, flist

    file_map, file_list = _list_files()
    raw = None
    content = ""
    my_file = angular_safe(request.args.get("fname", None))

    if my_file and my_file in file_list:
        data = codecs.open(os.path.join(config.ui.install_path, my_file), "rb", "utf-8").read()
        content = markdown.markdown(data)
        basedir = os.path.dirname(my_file)
        content = Markup(re.sub(r'href="(?!(http|ftp))', r'href="documentation.html?fname=%s/' % basedir, content))

        if my_file == "assemblyline/docs/markdown_documentation_example.md":
            raw = data

    return custom_render("admin_documentation.html", content=content, raw=raw,
                         file_map=file_map, fname=my_file, **kwargs)


@views.route("/admin/errors.html")
@protected_renderer(require_admin=True, audit=False)
def admin_errors(**kwargs):
    query = angular_safe(request.args.get('filter', ""))
    if query:
        query = query.replace("\\", "\\\\")
        query = query.replace("'", "\\'")
    return custom_render("admin_errors.html", filter=query, **kwargs)


@views.route("/admin/hosts.html")
@protected_renderer(require_admin=True, audit=False)
@crossdomain(origin="*", methods=["HEAD", "GET", "CONNECT", "POST", "OPTIONS"])
def admin_hosts(**kwargs):
    return custom_render("admin_hosts.html", **kwargs)


@views.route("/admin/profiles.html")
@protected_renderer(require_admin=True, audit=False)
def admin_profiles(**kwargs):
    return custom_render("admin_profiles.html", **kwargs)


@views.route("/admin/provisioning.html")
@protected_renderer(require_admin=True, audit=False)
def admin_provisioning(**kwargs):
    return custom_render("admin_provisioning.html", **kwargs)


@views.route("/admin/seed.html")
@protected_renderer(require_admin=True, audit=False)
def admin_seed(**kwargs):
    return custom_render("admin_seed.html", **kwargs)


@views.route("/admin/services.html")
@protected_renderer(require_admin=True, audit=False)
def admin_services(**kwargs):
    return custom_render("admin_service_configs.html", **kwargs)


@views.route("/admin/site_map.html")
@protected_renderer(require_admin=True, audit=False)
def admin_site_map(**kwargs):
    return custom_render("admin_site_map.html", **kwargs)


@views.route("/admin/users.html")
@protected_renderer(require_admin=True, audit=False)
def admin_user(**kwargs):
    return custom_render("admin_users.html", **kwargs)


@views.route("/admin/virtual_machines.html")
@protected_renderer(require_admin=True, audit=False)
def admin_vm(**kwargs):
    return custom_render("admin_virtual_machines.html", **kwargs)
