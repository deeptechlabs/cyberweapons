import logging

from flask import Flask

from al_ui.api_base import api
from al_ui.apiv3.alert import alert_api
from al_ui.apiv3.authentication import auth_api
from al_ui.apiv3.bundle import bundle_api
from al_ui.apiv3.controller import controller_api
from al_ui.apiv3.core import apiv3
from al_ui.apiv3.dashboard import dashboard_api
from al_ui.apiv3.error import error_api
from al_ui.apiv3.file import file_api
from al_ui.apiv3.hash_search import hash_search_api
from al_ui.apiv3.help import help_api
from al_ui.apiv3.heuristics import heuristics_api
from al_ui.apiv3.host import host_api
from al_ui.apiv3.ingest import ingest_api
from al_ui.apiv3.live import live_api
from al_ui.apiv3.profile import profile_api
from al_ui.apiv3.provisioning import provisioning_api
from al_ui.apiv3.proxy import proxy
from al_ui.apiv3.search import search_api
from al_ui.apiv3.seed import seed_api
from al_ui.apiv3.service import service_api
from al_ui.apiv3.signature import signature_api
from al_ui.apiv3.submission import submission_api
from al_ui.apiv3.submit import submit_api
from al_ui.apiv3.u2f import u2f_api
from al_ui.apiv3.ui import ui_api
from al_ui.apiv3.user import user_api
from al_ui.apiv3.vm import vm_api
from al_ui.apiv3.workflow import workflow_api
from al_ui.error import errors
from al_ui.views import views

from al_ui import config
from assemblyline.al.common import forge
from assemblyline.al.common.security import generate_async_keys

context = forge.get_ui_context()
register_site_specific_routes = context.register_site_specific_routes

##########################
# App settings
app = Flask("alui")
app.logger.setLevel(60)  # This completely turns off the flask logger
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SECRET_KEY=config.SECRET_KEY,
    PREFERRED_URL_SCHEME='https'
)

app.register_blueprint(controller_api)
app.register_blueprint(api)
app.register_blueprint(apiv3)
app.register_blueprint(auth_api)
app.register_blueprint(alert_api)
app.register_blueprint(bundle_api)
app.register_blueprint(dashboard_api)
app.register_blueprint(errors)
app.register_blueprint(error_api)
app.register_blueprint(file_api)
app.register_blueprint(hash_search_api)
app.register_blueprint(help_api)
app.register_blueprint(heuristics_api)
app.register_blueprint(host_api)
app.register_blueprint(ingest_api)
app.register_blueprint(live_api)
app.register_blueprint(profile_api)
app.register_blueprint(provisioning_api)
app.register_blueprint(proxy)
app.register_blueprint(search_api)
app.register_blueprint(seed_api)
app.register_blueprint(service_api)
app.register_blueprint(signature_api)
app.register_blueprint(submission_api)
app.register_blueprint(submit_api)
app.register_blueprint(u2f_api)
app.register_blueprint(ui_api)
app.register_blueprint(user_api)
app.register_blueprint(views)
app.register_blueprint(vm_api)
app.register_blueprint(workflow_api)

register_site_specific_routes(app)

if config.config.auth.get('encrypted_login', True):
    if not config.STORAGE.get_blob('id_rsa'):
        public_key, private_key = generate_async_keys(key_size=config.config.ui.get('rsa_key_size', 2048))
        config.STORAGE.save_blob('id_rsa.pub', public_key)
        config.STORAGE.save_blob('id_rsa', private_key)


def main():
    app.logger.setLevel(logging.INFO)
    if config.PROFILE:
        from werkzeug.contrib.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[30])
    print app.url_map
    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", debug=False)


if __name__ == '__main__':
    main()
