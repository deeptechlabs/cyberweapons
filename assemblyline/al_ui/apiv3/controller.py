
import uuid

from assemblyline.al.core.controller import ControllerClient
from assemblyline.al.core.agents import ServiceAgentClient
from al_ui.api_base import api_login, make_api_response
from al_ui.apiv3 import core

SUB_API = 'controller'
controller_api = core.make_subapi_blueprint(SUB_API)
controller_api._doc = "Control processing nodes"


@controller_api.route("/pause/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def pause_tasks(mac, **_):
    """
    Ask a node terminate all it's current tasks and stop processing new tasks
    
    Variables:
    mac       => mac address of the node
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the 
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}
    
    agent = ServiceAgentClient(sender=response.get("message_id", "*"), async=True)
    agent.drain(mac)
    
    return make_api_response(response)


@controller_api.route("/resume/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def resume_tasks(mac, **_):
    """
    Ask a node to resume task processing

    Variables:
    mac       => mac address of the node

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}

    agent = ServiceAgentClient(sender=response.get("message_id", "*"), async=True)
    agent.undrain(mac)

    return make_api_response(response)


@controller_api.route("/restart/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def restart_hostagent(mac, **_):
    """
    Ask a node to restart it's hostagent

    Variables:
    mac       => mac address of the node

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}

    agent = ControllerClient(sender=response.get("message_id", "*"), async=True)
    agent.restart(mac)

    return make_api_response(response)


@controller_api.route("/start/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def start_hostagent(mac, **_):
    """
    Ask a node to start it's hostagent

    Variables:
    mac       => mac address of the node

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}

    agent = ControllerClient(sender=response.get("message_id", "*"), async=True)
    agent.start(mac)

    return make_api_response(response)


@controller_api.route("/status/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def status_hostagent(mac, **_):
    """
    Get the status of a node's hostagent

    Variables:
    mac       => mac address of the node

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}

    agent = ControllerClient(sender=response.get("message_id", "*"), async=True)
    agent.status(mac)

    return make_api_response(response)


@controller_api.route("/stop/<mac>/", methods=["GET"])
@api_login(require_admin=True)
def stop_hostagent(mac, **_):
    """
    Ask a node to stop it's hostagent

    Variables:
    mac       => mac address of the node

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "message_id": UUID }  # UUID to look for in the
                            # control channel to get the
                            # result of this request
    """
    response = {"message_id": uuid.uuid4().get_hex()}

    agent = ControllerClient(sender=response.get("message_id", "*"), async=True)
    agent.stop(mac)

    return make_api_response(response)
