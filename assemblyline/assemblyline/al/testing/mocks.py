from assemblyline.al.common.transport.local import TransportLocal


class MockResubmissionClient(object):
    """A mock resubmission client used for testing. It places the resubmissions
       onto the list provided instead of sending to the submission server."""

    def __init__(self, children, supplementary, datastore=None):
        self.children = children
        self.supplementary = supplementary

    def submit_local_files(self, extracted, **kwargs):
        self.children.append((extracted, kwargs))
        return {path: {} for path in extracted}

    def transfer_local_files(self, extracted, **kwargs):
        self.supplementary.append((extracted, kwargs))
        return {path: {} for path in extracted}, {}

    def submit_supplementary_files(self, extracted, **kwargs):
        pass


def get_mock_submit_client(children, supplementary, datastore=None):
    return MockResubmissionClient(children, supplementary)


class MockServiceResultStore(object):
    """A mock result store (just interface used by services for now).

    This is used during the service unit tests. Results are place on the lists
    provided instead of being send to real storage backend."""

    def __init__(self, results, errors):
        self.results = results
        self.errors = errors

    def save_result(self, name, version, cfgkey, srl, classification, result):
        key = self._get_result_key(name, version, cfgkey, srl)
        self.results[key] = result
        return key

    def save_error(self, name, version, cfgkey, task):
        srl = task.srl
        result = task.as_service_result()
        key = self._get_result_key(name, version, cfgkey, srl)
        self.errors[key] = result
        return key

    def lookup_result(self, service_name, version, conf_key, srl):
        key = self._get_result_key(service_name, version, conf_key, srl)
        return key, self.results.get(key, None)

    def _get_result_key(self, service_name, version, conf_key, srl):
        return '.'.join([srl, service_name, version, conf_key])


def get_mock_result_store(results, errors):
    return MockServiceResultStore(results, errors)


def get_local_transport(file_base='/'):
    return TransportLocal(file_base, normalize=lambda x: x)


class MockDispatchCollector(object):

    def __init__(self):
        self.acks = []
        self.serviced_ok = []
        self.serviced_fail_nonrecoverable = []
        self.serviced_fail_recoverable = []
        self.unsupported = []

    def get_acks(self):
        return self.acks

    def get_unrecognized(self):
        return self.unsupported

    def get_serviced_results(self):

        return (self.serviced_ok,
                self.serviced_fail_nonrecoverable,
                self.serviced_fail_recoverable)

    def __str__(self):
        return "\n\tAcks:{0}\n\tSuccess:{1}\n\tFailures (Recoverable):{2}\n\tFailures (NonRecoverable):{3}\n\tUnrecognized:{4}".format(
            len(self.acks), len(self.serviced_ok), len(self.serviced_fail_recoverable),
            len(self.serviced_fail_nonrecoverable), len(self.unsupported))

    def send_raw(self, response):

        print "callback with response: %s" % str(response)
        state = response['state']
        if state == 'acknowledged':
            self.acks.append(response)
        elif state == 'serviced':
            status = response['response']['status']
            if status == 'OK':
                self.serviced_ok.append(response)
            elif status == 'FAIL_NONRECOVERABLE':
                self.serviced_fail_nonrecoverable.append(response)
            elif status == 'FAIL_RECOVERABLE':
                self.serviced_fail_recoverable.append(response)
            else:
                self.unsupported.append(response)
        else:
            self.unsupported.append(response)
