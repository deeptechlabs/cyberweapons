#!/usr/bin/env python

import json
import logging
import pprint
import psutil
import subprocess
import threading
import time


from assemblyline.common import isotime, net
from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.al.common import forge, log as al_log
from assemblyline.al.common.message import Message, reply_to_rpc, send_rpc_comms_queue, MT_CONTROLLERHEARTBEAT
from assemblyline.al.common.queue import CommsQueue, LocalQueue

config = forge.get_config()


class RemoteShutdownInterrupt(Exception):
    pass


class UnsupportedRequestError(Exception):
    pass


class ProvisioningError(Exception):
    pass


class ControllerRequest(Message):
    """ Convenience for Controller specific Message's."""
    START = 'start'
    STOP = 'stop'
    RESTART = 'restart'
    STATUS = 'status'
    HEARTBEAT = 'heartbeat'
    VALID_REQUESTS = [START, STOP, RESTART, STATUS]

    # noinspection PyUnusedLocal
    def __init__(self, to, mtype, body, sender=None, reply_to=None):
        super(ControllerRequest, self).__init__(to, mtype, sender, reply_to=None, body=body)

    @classmethod
    def parse(cls, raw):
        return Message.parse(raw)

    @classmethod
    def is_controller_request(cls, msg):
        return msg.mtype in cls.VALID_REQUESTS


def make_response(success=False, **kwargs):
    response = {
        'success': success,
    }
    response.update(kwargs)
    return response


class HostController(object):
    def __init__(self):
        self.mac = net.get_mac_address()
        self.store = forge.get_datastore()
        self.log = logging.getLogger('assemblyline.control')
        self.log.info('Starting Controller: MAC[%s] STORE[%s]' % (self.mac, self.store))

        # This hosts registration from riak (Hosts tab in UI).
        self.jobs = LocalQueue()
        self.last_heartbeat = 0
        self.rpc_handlers = {
            ControllerRequest.HEARTBEAT: self.controller_heartbeat,
            ControllerRequest.START: self.hostagent_start,
            ControllerRequest.STOP: self.hostagent_stop,
            ControllerRequest.RESTART: self.hostagent_restart,
            ControllerRequest.STATUS: self.hostagent_status,
        }
        self._should_run = True
        self.executor_thread = None
        self.heartbeat_thread = None

    @staticmethod
    def _run(cmd):
        p = subprocess.Popen(cmd,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (out, err) = p.communicate()
        rc = p.returncode
        return rc, out.strip(), err.strip()
        
    def _build_heartbeat(self):
        heartbeat = {'mac': self.mac, 'time': isotime.now_as_iso(), 'resources': {
            'cpu_usage.percent': psutil.cpu_percent(),
            'mem_usage.percent': psutil.phymem_usage().percent,
            'disk_usage.percent': psutil.disk_usage('/').percent,
            'disk_usage.free': psutil.disk_usage('/').free
        }}
        return heartbeat

    def controller_heartbeat(self, _):
        return make_response(True, heartbeat=json.dumps(self._build_heartbeat()))

    def hostagent_stop(self, _):
        cmdline = "sudo service hostagent stop"
        (rc, out, err) = self._run(cmdline)
        if rc != 0:
            response = make_response(False, stdout=out, stderr=err)
        else:
            response = make_response(True, status='stopped')
        return response
    
    def hostagent_start(self, _):
        cmdline = "sudo service hostagent start"
        (rc, out, err) = self._run(cmdline)
        if rc != 0:
            response = make_response(False, stdout=out, stderr=err)
        else:
            response = make_response(True, status='started')
        return response

    def hostagent_restart(self, _):
        cmdline = "sudo service hostagent restart"
        (rc, out, err) = self._run(cmdline)
        if rc != 0:
            response = make_response(False, stdout=out, stderr=err)
        else:
            response = make_response(True, status='restarted')
        return response

    def hostagent_status(self, _):
        cmdline = "sudo service hostagent status"
        (rc, out, err) = self._run(cmdline)
        if rc != 0:
            return make_response(False, stdout=out, stderr=err)
        else:
            return make_response(True, status=out)

    @staticmethod
    def _handle_unknown_request(msg):
        raise Exception('Unknown message type: %s', msg.mtype)

    @staticmethod
    def _handle_exception(msg, e):
        return 'Exception while processing msg %s: %s' % (msg.mtype, str(e))

    def _handle_request(self, msg):
        self.log.info('Processing RPC: %s', msg.mtype)
        handler = self.rpc_handlers.get(msg.mtype, self._handle_unknown_request)
        return handler(msg)

    def _heartbeat_thread_main(self):
        while self._should_run:
            # TODO: add locking
            self.log.debug('Sending heartbeat')
            heartbeat = self._build_heartbeat()
            msg = Message(to="*", 
                          sender='controller',
                          mtype=MT_CONTROLLERHEARTBEAT,
                          body=heartbeat)
            CommsQueue('status').publish(msg.as_dict())
            time.sleep(config.system.update_interval)

    # noinspection PyBroadException
    def _rpc_executor_thread_main(self):
        qname = 'Controller.' + self.mac
        self.log.info("Listening for RPCs on " + qname)
        rpc = CommsQueue(qname)
        while self._should_run:
            try:
                self.log.debug('Checking for RPCs')
                raw = next(rpc.listen())
                if not raw or 'data' not in raw:
                    continue

                self.log.info("RAW RPC:\n%s" % pprint.pformat(raw))
                raw = json.loads(raw['data'])
                msg = None
                error = None
                try:
                    msg = ControllerRequest.parse(raw)
                except Exception as e:  # pylint:disable=W0703
                    self.log.exception('While processing rpc: %s', raw)
                    error = str(e)

                if msg:
                    self.jobs.push(msg)
                else:
                    reply_to_rpc(raw, response_body=error, succeeded=False)
            except KeyboardInterrupt:
                self._should_run = False
                self.log.error('Thread got CTL-C in consumer thread.')
                return
            except Exception:
                self.log.exception('Unhandled Exception in consumer thread.')
                time.sleep(2)
                continue

    @staticmethod
    def shutdown(msg):
        raise RemoteShutdownInterrupt(str(msg))

    def stop(self):
        self._should_run = False
        pass

    def run(self):
        self.executor_thread = threading.Thread(
            target=self._rpc_executor_thread_main, 
            name='controller_rpc_consumer')
        self.executor_thread.daemon = True
        self.executor_thread.start()

        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_thread_main, 
            name='heartbeat')
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()

        while self._should_run:
            job = self.jobs.pop(timeout=0.5)
            if not job:
                self.log.debug("No jobs. Waiting...")
                continue

            succeeded = True
            try:
                result = self._handle_request(job)
            except RemoteShutdownInterrupt:
                reply_to_rpc(job, response_body='Controller shutting down.', succeeded=True)
                raise
            except Exception as e:  # pylint:disable=W0703
                succeeded = False
                result = 'Error while completing job: %s' % str(e)
                self.log.exception('while completing job')

            reply_to_rpc(job, response_body=result, succeeded=succeeded)

        self.log.info('_should_run is false. exiting.')
        return

    def serve_forever(self):
        try:
            # Inject a message onto the controller queue.
            self.run()
        except KeyboardInterrupt:
            self.log.info('Shutting down due to signal.')
            self.stop()
        except RemoteShutdownInterrupt as ri:
            msg = 'Shutting down due to remote command: %s' % ri
            self.log.info(msg)
            self.stop()
        except Exception as ex:
            msg = 'Shutting down due to unhandled exception: %s' % get_stacktrace_info(ex)
            self.log.error(msg)
            self.stop()


class AgentClient(object):

    def __init__(self, async=False, sender=None):
        """ If sender is not specified the local MAC is used """
        self.sender = sender or net.get_mac_for_ip(net.get_hostip())
        self.async = async

    def _send_agent_rpc(self, mac, command, args=None):
        result = send_rpc_comms_queue(ControllerRequest(
            to=mac, mtype=command, body=args,
            sender=self.sender), async=self.async)

        if not self.async:
            if result:
                return result.body
            return 'timeout'
        else:
            return result


class ControllerClient(AgentClient):

    def __init__(self, sender=None, async=False):
        super(ControllerClient, self).__init__(async, sender)

    def heartbeat(self, mac):
        return self._send_agent_rpc('Controller.' + mac, ControllerRequest.HEARTBEAT)

    # noinspection PyUnusedLocal
    def stop(self, mac):
        return self._send_agent_rpc('Controller.' + mac, ControllerRequest.STOP)

    # noinspection PyUnusedLocal
    def start(self, mac):
        return self._send_agent_rpc('Controller.' + mac, ControllerRequest.START)

    # noinspection PyUnusedLocal
    def restart(self, mac):
        return self._send_agent_rpc('Controller.' + mac, ControllerRequest.RESTART)

    # noinspection PyUnusedLocal
    def status(self, mac):
        return self._send_agent_rpc('Controller.' + mac, ControllerRequest.STATUS)

if __name__ == '__main__':
    al_log.init_logging('controller')

    hc = HostController()
    hc.serve_forever()
    hc.log.info("Controller Terminated")
