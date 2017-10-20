
from assemblyline.al.common.queue import CommsQueue, NamedQueue, reply_queue_name


class MessageError(Exception):
    pass

MT_DISPHEARTBEAT = 'DispHeartbeat'
MT_INGESTHEARTBEAT = 'IngestHeartbeat'
MT_SVCHEARTBEAT = 'SvcHeartbeat'
MT_CONTROLLERHEARTBEAT = 'CtlHeartbeat'
MT_HARDDRIVE_FAILURES = "HardDriveFailures"
MT_ALERT_CREATED = "AlertCreated"


def send_rpc_comms_queue(msg, response_timeout=10, async=False):
    assert isinstance(msg, Message)
    if not async:
        msg.reply_to = reply_queue_name('ssrpc')
        CommsQueue(msg.to).publish(msg.as_dict())
        result = NamedQueue(msg.reply_to).pop(timeout=response_timeout)
        if not result:
            return None
        return Message.parse(result)
    else:
        msg.reply_to = '*'
        CommsQueue(msg.to).publish(msg.as_dict())
        return


def send_rpc(msg, response_timeout=10, async=False):
    assert isinstance(msg, Message)
    if not async:
        msg.reply_to = reply_queue_name('ssrpc')
        NamedQueue(msg.to).push(msg.as_dict())
        result = NamedQueue(msg.reply_to).pop(timeout=response_timeout)
        if not result:
            return None
        return Message.parse(result)
    else:
        msg.reply_to = '*'
        NamedQueue(msg.to).push(msg.as_dict())
        return


def reply_to_rpc(request_msg, response_body, succeeded=True):
    if isinstance(request_msg, Message):
        rpc_channel = request_msg.reply_to
        to = request_msg.sender
        mtype = request_msg.mtype
        sender = request_msg.to
    else:  # raw dictionary
        rpc_channel = request_msg['reply_to']
        to = request_msg['sender']
        mtype = request_msg['mtype']
        sender = request_msg['to']

    msg = Message(
        to=to, 
        mtype=mtype,
        sender=sender, 
        succeeded=succeeded,
        body=response_body).as_dict()

    if rpc_channel == '*' or rpc_channel == u'*':
        CommsQueue('status').publish(msg)
    else:
        NamedQueue(rpc_channel).push(msg)


class Message(object):
    """
    Message objects:
        to          ---    recipient list (empty for broadcast)
        mtype       ---    message type
        sender      ---    message originator
        reply_to    ---    response recipient list (empty for broadcast)
        mid         ---    message id (uuid generated on instantiation)
        body        ---    message content -- must be json-serializable   
        succeeded    ---   If true body is result else body is error description.
    """
    
    # pylint:disable=W0231
    def __init__(self,
                 to,
                 mtype,
                 sender=None,
                 reply_to=None,
                 succeeded=True,
                 body=None):
        self.sender = sender
        self.to = to
        self.reply_to = reply_to
        self.mtype = mtype
        self.succeeded = succeeded
        self.body = body

        if not self.mtype:
            raise MessageError('Missing mandatory mtype field.')
        
    def as_dict(self):
        return self.__dict__

    @classmethod
    def parse(cls, raw):
        try:
            sender = raw['sender']
            to = raw['to']
            reply_to = raw['reply_to']
            mtype = raw['mtype']
            body = raw['body']
            succeeded = raw.get('succeeded', True)
            return Message(to, mtype, sender, reply_to, succeeded, body)
        except KeyError, e:
            raise MessageError('Message missing field: %s' % e.message)
