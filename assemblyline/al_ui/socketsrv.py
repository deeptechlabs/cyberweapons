import json
import logging

from flask import Flask, request, session
from flask_socketio import SocketIO, emit

from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.queue import CommsQueue, NamedQueue
from assemblyline.al.common.remote_datatypes import Hash

config = forge.get_config()
datastore = forge.get_datastore()
classification = forge.get_classification()

app = Flask(__name__)
app.config['SECRET_KEY'] = config.ui.secret_key
socketio = SocketIO(app)

al_log.init_logging("ui")
AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui.socketio')

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port,
                  db=config.core.redis.nonpersistent.db)


def get_user_info(resquest_p, session_p):
    uname = None
    current_session = KV_SESSION.get(session_p.get("session_id", None))
    if current_session:
        current_session = json.loads(current_session)
        if resquest_p.headers.get("X-Forward-For", None) == current_session.get('ip', None) and \
                resquest_p.headers.get("User-Agent", None) == current_session.get('user_agent', None):
            uname = current_session['username']

    user_classification = None
    if uname:
        user = datastore.get_user(uname)
        if user:
            user_classification = user.get('classification', None)

    return {
        'uname': uname,
        'classification': user_classification,
        'ip': resquest_p.headers.get("X-Forward-For", None)
    }


# noinspection PyBroadException
@socketio.on('alert')
def alert_on(data):
    info = get_user_info(request, session)

    if info.get('uname', None) is None:
        return

    LOGGER.info("[%s@%s] SocketIO:Alert - Event received => %s" % (info.get('uname', None), info['ip'], data))
    if AUDIT:
        AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
                                                 info.get('classification', classification.UNRESTRICTED),
                                                 "socketsrv_alert_on"))
    emit('connected', data)

    q = CommsQueue('alerts', private=True)
    try:
        for msg in q.listen():
            if msg['type'] == "message":
                data = json.loads(msg['data'])
                if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
                                                data.get('body', {}).get('classification',
                                                                         classification.UNRESTRICTED)):
                    emit('AlertCreated', data)
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Alert" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Alert - Connection to client was terminated" %
                    (info.get('uname', None), info['ip']))
        if AUDIT:
            AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
                                                    info.get('classification', classification.UNRESTRICTED),
                                                    "socketsrv_alert_on"))


# noinspection PyBroadException
@socketio.on('monitor')
def monitoring_on(data):
    info = get_user_info(request, session)

    if info.get('uname', None) is None:
        return

    LOGGER.info("[%s@%s] SocketIO:Monitor - Event received => %s" % (info.get('uname', None), info['ip'], data))
    emit('connected', data)
    
    q = CommsQueue('status', private=True)
    try:
        for msg in q.listen():
            if msg['type'] == "message":
                data = json.loads(msg['data'])
                emit(data['mtype'], data)
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Monitor" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Monitor - Connection to client was terminated" % (info.get('uname', None),
                                                                                        info['ip']))


# noinspection PyBroadException
@socketio.on('listen')
def listen_on(data):
    info = get_user_info(request, session)

    if info.get('uname', None) is None:
        return
    
    LOGGER.info("[%s@%s] SocketIO:Listen - Event received => %s" % (info.get('uname', None), info['ip'], data))
    
    try:
        u = NamedQueue(data['wq_id'], private=True)
        if data['from_start']:
            msg = u.pop(timeout=15)

            if msg is None:
                emit('error', {'err_msg': 'Never got any response from the dispatcher. Try reloading the page...',
                               'status_code': 404, 'msg': None})
                LOGGER.info("[%s@%s] SocketIO:Listen - Timeout reached. Event terminated." % (info.get('uname', None),
                                                                                              info['ip']))
                return
            elif msg['status'] == 'START':
                emit('start', {'err_msg': None, 'status_code': 200, 'msg': "Start listening..."})
            elif msg['status'] == 'STOP':
                emit('stop', {'err_msg': None, 'status_code': 200, 'msg': "All messages received, closing queue..."})
                LOGGER.info("[%s@%s] SocketIO:Listen - Event terminated gracefully." % (info.get('uname', None),
                                                                                        info['ip']))
                return
            else:
                emit('error', {'err_msg': 'Unexpected status code for the first message',
                               'status_code': 500, 'msg': msg})
                LOGGER.info("[%s@%s] SocketIO:Listen - Unexpected message received. "
                            "Event terminated." % (info.get('uname', None), info['ip']))
                return
                
        while True:
            msg = u.pop(timeout=300)

            if msg is None:
                emit('error', {'err_msg': 'Never got any response from the dispatcher. Try reloading the page...',
                               'status_code': 404, 'msg': None})
                LOGGER.info("[%s@%s] SocketIO:Listen - Timeout reached. Event terminated." % (info.get('uname', None),
                                                                                              info['ip']))
                break
            if msg['status'] == 'STOP':
                emit('stop', {'err_msg': None, 'status_code': 200, 'msg': "All messages received, closing queue..."})
                LOGGER.info("[%s@%s] SocketIO:Listen - Event terminated gracefully." % (info.get('uname', None),
                                                                                        info['ip']))
                break
            elif msg['status'] == 'OK':
                emit('cachekey', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']})
            elif msg['status'] == 'FAIL':
                emit('cachekeyerr', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']})
                
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Listen" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Listen - Connection to client was terminated" % (info.get('uname', None),
                                                                                       info['ip']))


# noinspection PyBroadException
@socketio.on('submission')
def submission_on(data):
    info = get_user_info(request, session)

    if info.get('uname', None) is None:
        return

    LOGGER.info("[%s@%s] SocketIO:Submission - Event received => %s" % (info.get('uname', None), info['ip'], data))
    if AUDIT:
        AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
                                                 info.get('classification', classification.UNRESTRICTED),
                                                 "socketsrv_submission_on"))
    emit('connected', data)

    q = CommsQueue('traffic', private=True)
    try:
        for msg in q.listen():
            if msg['type'] == "message":
                body = json.loads(msg['data'])
                submission_classification = body.get('body', {}).get('classification', classification.UNRESTRICTED)
                message = {
                    'body': body,
                    'mtype': 'SubmissionIngested',
                    'reply_to': None,
                    'sender': u'middleman',
                    'succeeded': True,
                    'to': u'*'
                }

                if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
                                                submission_classification):
                    emit('SubmissionIngested', message)
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Submission" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Submission - Connection to client was terminated" %
                    (info.get('uname', None), info['ip']))
        if AUDIT:
            AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
                                                    info.get('classification', classification.UNRESTRICTED),
                                                    "socketsrv_submission_on"))


if __name__ == '__main__':
    print app.url_map
    socketio.run(app, host="0.0.0.0", port=5002)
