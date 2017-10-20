#!/usr/bin/env python
from __future__ import absolute_import

import os
import unittest

from assemblyline.al.common import forge
from assemblyline.al.common.task import Task
from assemblyline.al.testing import mocks

SHA256_CORPUS_DIR = os.path.expanduser(r'~/.al/filestore/by_sha256')

class ServiceTestCase(unittest.TestCase):

    def setUp(self, service_cls, service_cfg):
        super(ServiceTestCase, self).setUp()

        self.service_cls = service_cls
        self.service_cfg = service_cfg
        self.results = {}
        self.result_errors = {}
        self.dispatch_collector = mocks.MockDispatchCollector()
        self.children = []
        
        self.acks = []
        self.fail_recoverable = []
        self.fail_nonrecoverable = []
        self.succeeded = []
        self.unrecognized = []

        import functools
        forge.get_filestore = lambda: mocks.get_local_transport(file_base=SHA256_CORPUS_DIR)
        forge.get_submit_client = functools.partial(
            mocks.get_mock_submit_client, self.children)
        forge.get_dispatch_queue = lambda: self.dispatch_collector
        forge.get_datastore = functools.partial(
            mocks.get_mock_result_store,
            self.results,
            self.result_errors)
 
    def run_task(self, task):
        service = self.service_cls(self.service_cfg)
        service.start_service()
        service.handle_task(task)
        service.stop_service()
        self._finalize_results()

    def _finalize_results(self):
        self.acks = self.dispatch_collector.get_acks()
        (self.succeeded, 
         self.fail_nonrecoverable, 
         self.fail_recoverable) = self.dispatch_collector.get_serviced_results()

    def assert_result_counts(self, succeeded=0, fail_recoverable=0, fail_nonrecoverable=0, children=0, acks=None):

        if succeeded is not None:
            self.assertEqual(succeeded, len(self.succeeded))

        if fail_recoverable is not None:
            self.assertEqual(fail_recoverable, len(self.fail_recoverable))

        if fail_nonrecoverable is not None:
            self.assertEqual(fail_nonrecoverable, len(self.fail_nonrecoverable))

        if children is not None:
            self.assertEqual(children, len(self.children))

        if acks is not None:
            self.assertEqual(acks, len(self.acks))

        self.assertEquals(len(self.unrecognized), 0)

    def dump_stats(self):
        self._finalize_results()
        print 'DispatchResponses: %s' % len(self._dispatch_responses)
        print '\tAcks: %s' % len(self.acks)
        print '\tFail(Recoverable): %s' % len(self.fail_recoverable)
        print '\tFail(NonRecoverable): %s' % len(self.fail_nonrecoverable)
        print '\tOK: %s' % len(self.succeeded)
        print 'Results (GOOD): %s' % len(self.results)
        print 'Results (ERROR): %s' % len(self.result_errors)
        print 'Children: %s' % len(self.children)
