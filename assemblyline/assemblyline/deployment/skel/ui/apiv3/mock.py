from assemblyline.al.common import forge
from al_ui.apiv3 import core
from al_ui.api_base import api_login, make_api_response

SUB_API = 'mock'

Classification = forge.get_classification()

mock_api = core.make_subapi_blueprint(SUB_API)
mock_api._doc = "Mock API"


@mock_api.route("/<value>/", methods=["GET"])
@api_login()
def replay_value(value, **kwargs):
    """
    Make your own API here
    """
    return make_api_response({"success": True, "value": value})

