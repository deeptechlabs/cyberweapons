import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import uuid

from random import random

from assemblyline.al.common.counter import Counters
from assemblyline.al.common.heuristics import get_heuristics_form_class
from assemblyline.al.common.queue import NamedQueue
from assemblyline.al.common.remote_datatypes import ExpiringSet, ExpiringHash
from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.task import Child, Task, get_service_overrides
from assemblyline.al.core.datastore import uncompress_riak_key
from assemblyline.al.core.filestore import CorruptedFileStoreException
from assemblyline.common import digests
from assemblyline.common import exceptions
from assemblyline.common import net
from assemblyline.common.charset import safe_str
from assemblyline.common.concurrency import execute_concurrently
from assemblyline.common.isotime import now_as_iso, now
from assemblyline.common.path import modulepath
from assemblyline.common.properties import classproperty
from assemblyline.al.common import forge, version

config = forge.get_config()
Classification = forge.get_classification()
persistent_settings = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}
non_persistent_settings = {
    'db': config.core.redis.nonpersistent.db,
    'host': config.core.redis.nonpersistent.host,
    'port': config.core.redis.nonpersistent.port,
}


class ServiceDefinitionException(Exception):
    pass


class UpdaterFrequency(object):
    MINUTE = 60
    QUARTER_HOUR = MINUTE * 15
    HALF_HOUR = MINUTE * 30
    HOUR = MINUTE * 60
    QUAD_HOUR = HOUR * 4
    QUARTER_DAY = HOUR * 6
    HALF_DAY = HOUR * 12
    DAY = HOUR * 24

    @staticmethod
    def is_valid(freq):
        try:
            int(freq)
        except ValueError:
            return False

        return freq >= UpdaterFrequency.MINUTE


class UpdaterType(object):
    BOX = 'box'
    CLUSTER = 'cluster'
    PROCESS = 'process'
    NON_BLOCKING = 'non_blocking'

    @staticmethod
    def is_valid(utype):
        return utype in [UpdaterType.BOX, UpdaterType.CLUSTER, UpdaterType.PROCESS, UpdaterType.NON_BLOCKING]

    @staticmethod
    def blocking_types():
        return [
            UpdaterType.BOX,
            UpdaterType.CLUSTER,
            UpdaterType.PROCESS
        ]

    @staticmethod
    def unique_updater_types():
        return [
            UpdaterType.BOX,
            UpdaterType.CLUSTER
        ]


class Category(object):
    ANTIVIRUS = 'Antivirus'
    EXTRACTION = 'Extraction'
    FILTERING = 'Filtering'
    METADATA = 'Metadata'
    NETWORKING = 'Networking'
    STATIC_ANALYSIS = 'Static Analysis'
    DYNAMIC_ANALYSIS = 'Dynamic Analysis'
    SYSTEM = 'System'
    TEST = 'Test'

    @staticmethod
    def get_all():
        return [Category.ANTIVIRUS,
                Category.EXTRACTION,
                Category.FILTERING,
                Category.METADATA,
                Category.NETWORKING,
                Category.STATIC_ANALYSIS,
                Category.DYNAMIC_ANALYSIS,
                Category.SYSTEM,
                Category.TEST]


class Stage(object):
    SETUP = 'SETUP'
    FILTER = 'FILTER'
    EXTRACT = 'EXTRACT'
    CORE = 'CORE'
    SECONDARY = 'SECONDARY'
    POST = 'POST'
    TEARDOWN = 'TEARDOWN'

    @staticmethod
    def get_ordered():
        return [Stage.SETUP,
                Stage.FILTER,
                Stage.EXTRACT,
                Stage.CORE,
                Stage.SECONDARY,
                Stage.POST,
                Stage.TEARDOWN]


class ServiceRequest(object):
    def __init__(self, service, task):
        self.srl = task.srl
        self.sid = task.sid
        self.config = task.config
        self.tag = task.tag
        self.md5 = task.md5
        self.sha1 = task.sha1
        self.sha256 = task.sha256
        self.priority = task.priority
        self.ignore_filtering = task.ignore_filtering
        self.task = task
        self.local_path = ''
        self.successful = True
        self.error_is_recoverable = True
        self.error_text = None
        self.current_score = task.max_score
        self.deep_scan = task.deep_scan
        self.extracted = task.extracted
        self.max_extracted = task.max_extracted
        self.path = task.path or task.sha256

        self._svc = service

    @property
    def result(self):
        return self.task.result

    @result.setter
    def result(self, value):
        self.task.result = value

    def add_extracted(self, name, text, display_name=None, classification=None, submission_tag=None):
        return self.task.add_extracted(
            name, text, display_name, classification or self._svc.SERVICE_CLASSIFICATION, submission_tag
        )

    def add_supplementary(self, name, text, display_name=None, classification=None):
        return self.task.add_supplementary(
            name, text, display_name, classification or self._svc.SERVICE_CLASSIFICATION
        )

    def download(self):
        sha256 = os.path.basename(self.srl)
        localpath = self.tempfile(sha256)
        self._svc.transport.download(self.srl, localpath)
        if not os.path.exists(localpath):
            raise Exception('Download failed. Not found on local filesystem')

        received_sha256 = digests.get_sha256_for_file(localpath)
        if received_sha256 != sha256:
            raise CorruptedFileStoreException('SHA256 mismatch between SRL and '
                                              'downloaded file. %s != %s' % (sha256, received_sha256))
        return localpath

    def drop(self):
        self.task.drop()

    def exclude_service(self, name):
        return self.task.exclude_service(name)

    def failed(self, msg):
        self.successful = False
        self.error_text = msg

    def get(self):
        data = self._svc.transport.get(self.srl)
        received_sha256 = hashlib.sha256(data).hexdigest()
        if received_sha256 != self.srl:
            raise CorruptedFileStoreException('SHA256 mismatch between SRL and '
                                              'downloaded file. %s != %s' % (self.srl, received_sha256))
        return data

    def get_param(self, name):
        params = {x['name']: x['default']
                  for x in config.services.master_list[self.task.service_name]['submission_params']}
        service_params = self.task.get_service_params(self.task.service_name)
        return service_params.get(name, params[name])

    def get_results(self):
        return [uncompress_riak_key(r, self.srl)
                for r in (self.task.results or [])]

    def get_tags(self):
        return ExpiringSet(self.task.get_tag_set_name()).members()

    def pop_param(self, name, default=None):
        service_params = self.task.get_service_params(self.task.service_name)
        return service_params.pop(name, default)

    def set_service_context(self, msg):
        self.task.report_service_context(msg)

    def set_save_result(self, v):
        self.task.save_result_flag = v

    def tempfile(self, sha256):
        return os.path.join(self._svc.working_directory, sha256)


class ServiceRequestBatch(object):
    def __init__(self, service, tasks):
        self._service = service
        self.requests = [ServiceRequest(service, t) for t in tasks]
        self.request_by_srl = {}
        self.batchid = uuid.uuid4().get_hex()
        self._index_requests()
        self.request_by_localpath = {}
        self.batch_working_dir = os.path.join(self._service.working_directory, self.batchid)

    def fail_all_in_batch(self, msg):
        for request in self.requests:
            request.failed(msg)

    def find_by_srl(self, srl):
        return self.request_by_srl.get(srl, None)

    def find_by_local_path(self, local_path):
        return self.request_by_localpath.get(local_path, None)

    def _index_by_localpath(self):
        for request in self.requests:
            if request.local_path:
                self.request_by_localpath[request.local_path] = request

    def _index_requests(self):
        for request in self.requests:
            self.request_by_srl[request.srl] = request

    # noinspection PyBroadException
    def delete_downloaded(self):
        try:
            if os.path.isdir(self.batch_working_dir):
                shutil.rmtree(self.batch_working_dir)
        except:  # pylint:disable=W0702
            self._service.log.warn('Could not delete batch download directory:%s',
                                   self.batch_working_dir)

    def download(self):
        download_directory = self.batch_working_dir
        os.makedirs(download_directory)

        for request in self.requests:
            local_path = ""
            try:
                local_path = os.path.join(download_directory,
                                          os.path.basename(request.srl))
                self._service.transport.download(request.srl, local_path)
                received_sha256 = digests.get_sha256_for_file(local_path)
                if received_sha256 != request.srl:
                    raise CorruptedFileStoreException('SHA256 mismatch between SRL and '
                                                      'downloaded file. %s != %s' % (request.srl, received_sha256))
                request.successful = True
                request.local_path = local_path
            except Exception as ex:  # pylint: disable=W0703
                self._service.log.error("Failed to download: %s - %s", local_path, str(ex))
                msg = exceptions.get_stacktrace_info(ex)
                request.successful = False
                request.error_text = msg
                if not "SHA256 mismatch" in ex.message:
                    request.error_is_recoverable = True

        # often batch services will know the filename that they processed
        # and want to get the original request associated with it.
        self._index_by_localpath()

        return download_directory


# Counters we will track.
CACHE_HIT = 'svc.cache_hit'
CACHE_MISS = 'svc.cache_miss'
CACHE_SKIPPED = 'svc.cache_skipped'
EXECUTE_START = 'svc.execute_start'
EXECUTE_DONE = 'svc.execute_done'
EXECUTE_FAIL_RECOV = 'svc.execute_fail_recov'
EXECUTE_FAIL_NONRECOV = 'svc.execute_fail_nonrecov'
JOB_SCORED = 'svc.job_scored'
JOB_NOT_SCORED = 'svc.job_not_scored'


class ServiceBase(object):  # pylint:disable=R0922

    # If a service indicates it is a BATCH_SERVICE, the driver will attempt to
    # spool multiple requests before invoking the services execute() method.
    BATCH_SERVICE = False

    SERVICE_ACCEPTS = '.*'
    SERVICE_REJECTS = 'empty|metadata/.*'

    SERVICE_CATEGORY = 'Uncategorized'
    SERVICE_CLASSIFICATION = Classification.UNRESTRICTED
    # The default cfg used when an instance of this service is created.
    # Override this in your subclass with sane defaults for your service.
    # Default service config is a key/value where the value can be str, bool, int or list. Nothing else
    SERVICE_DEFAULT_CONFIG = {}
    # The default submission parameters that will be made available to the users when they submit files to your service.
    # Override this in your subclass with sane defaults for your service.
    # Default submission params list of dictionary. Dictionaries must have 4 keys (default, name, type, value) where
    # default is the default value, name is the name of the variable, type is the type of data (str, bool, int or list)
    #  and value should be set to the same as default.
    SERVICE_DEFAULT_SUBMISSION_PARAMS = []
    SERVICE_DESCRIPTION = "N/A"
    SERVICE_DISABLE_CACHE = False
    SERVICE_ENABLED = False
    SERVICE_REVISION = '0'
    SERVICE_SAVE_RESULT = True
    SERVICE_SAFE_START = False
    SERVICE_STAGE = 'CORE'
    SERVICE_SUPPORTED_PLATFORMS = ['Linux']
    SERVICE_TIMEOUT = config.services.timeouts.default
    SERVICE_VERSION = '0'
    SERVICE_IS_EXTERNAL = False

    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 1024

    def __init__(self, cfg=None):
        # Start with default config and override that with anything provided.
        self.cfg = self.SERVICE_DEFAULT_CONFIG.copy()
        if cfg:
            self.cfg.update(cfg)

        # Initialize non trivial members in start_service rather than __init__.
        self.log = logging.getLogger('assemblyline.svc.%s' % self.SERVICE_NAME.lower())
        self.counters = None
        self.dispatch_queue = None
        self.result_store = None
        self.submit_client = None
        self.transport = None
        self.worker = None
        self._working_directory = None
        self._ip = '127.0.0.1'
        self.mac = net.get_mac_for_ip(net.get_hostip())
        self._updater = None
        self._updater_id = None
        self.submission_tags = {}

    @classmethod
    def list_heuristics(cls):
        return [x.to_dict() for x in get_heuristics_form_class(cls)]

    def start(self):
        pass

    def stop(self):
        pass

    def execute(self, request):
        raise NotImplementedError('execute() not implemented.')

    def sysprep(self):
        pass

    def get_service_params(self, task=None):
        params = {x['name']: x['default'] for x in config.services.master_list[self.SERVICE_NAME]['submission_params']}
        if task:
            params.update(task.get_service_params(self.SERVICE_NAME))
        return params

    def get_config_data(self, task):
        return self.get_service_params(task)

    def get_tool_version(self):
        return ''

    def get_counters(self):
        if not self.counters:
            return Counters()
        current = self.counters.copy()
        self.counters = Counters()
        self.counters['name'] = self.SERVICE_NAME
        self.counters['type'] = "service"
        self.counters['host'] = self._ip
        return current

    def import_service_deps(self):
        pass

    # noinspection PyBroadException
    @staticmethod
    def get_task_age(task):
        received = 0
        try:
            received = task.request.get('sent')
        except:  # pylint:disable=W0702
            pass
        if not received:
            return 0
        return time.time() - received

    @staticmethod
    def skip(_):
        return False

    @classmethod
    def validate_config_or_raise(cls):
        pass

    @staticmethod
    def _peek_from_queues(queue_list):
        for queue_name in queue_list:
            msg = NamedQueue(queue_name, **non_persistent_settings).peek_next()
            if msg is not None:
                return msg

        return None

    # ------- Block Services Functions -------- #
    def _block_for_updater(self):
        if self._updater_id is None:
            return

        queues = [
            "blk-%s-%s-%s" % (self.SERVICE_NAME, self.mac, self._updater_id),
            "blk-%s-%s" % (self.SERVICE_NAME, self.mac),
            "blk-%s" % self.SERVICE_NAME
        ]
        count = 0
        while self._peek_from_queues(queues) is not None:
            if count % 60 == 0:
                self.log.info("Execution blocked by updater. Waiting...")
            time.sleep(1)
            count += 1

        if count > 0:
            self.log.info("Updater has released execution!")

    def _block_process_execution(self, blk_id, ttl):
        queue_name = "blk-%s-%s-%s" % (self.SERVICE_NAME, self.mac, blk_id)
        NamedQueue(queue_name, ttl=ttl, **non_persistent_settings).push(now_as_iso())

    def _block_box_execution(self, ttl):
        queue_name = "blk-%s-%s" % (self.SERVICE_NAME, self.mac)
        NamedQueue(queue_name, ttl=ttl, **non_persistent_settings).push(now_as_iso())

    def _block_cluster_execution(self, ttl):
        queue_name = "blk-%s" % self.SERVICE_NAME
        NamedQueue(queue_name, ttl=ttl, **non_persistent_settings).push(now_as_iso())

    # ------- Unblock Services functions -------- #
    def _unblock_process_execution(self, blk_id):
        queue_name = "blk-%s-%s-%s" % (self.SERVICE_NAME, self.mac, blk_id)
        NamedQueue(queue_name, **non_persistent_settings).delete()

    def _unblock_box_execution(self):
        queue_name = "blk-%s-%s" % (self.SERVICE_NAME, self.mac)
        NamedQueue(queue_name, **non_persistent_settings).delete()

    def _unblock_cluster_execution(self):
        queue_name = "blk-%s" % self.SERVICE_NAME
        NamedQueue(queue_name, **non_persistent_settings).delete()

    # ------- Lock updater functions -------- #
    def _lock_box_updater(self, lck_id, ttl):
        queue_name = "uplk-%s-%s" % (self.SERVICE_NAME, self.mac)
        queue = NamedQueue(queue_name, ttl=ttl, **non_persistent_settings)
        queue.push(lck_id)
        return lck_id == queue.peek_next()

    def _lock_cluster_updater(self, lck_id, ttl):
        queue_name = "uplk-%s" % self.SERVICE_NAME
        queue = NamedQueue(queue_name, ttl=ttl, **non_persistent_settings)
        queue.push(lck_id)
        return lck_id == queue.peek_next()

    # -------- Release updater functions -------- #
    def _release_box_updater(self):
        queue_name = "uplk-%s-%s" % (self.SERVICE_NAME, self.mac)
        NamedQueue(queue_name, **non_persistent_settings).delete()

    def _release_cluster_updater(self):
        queue_name = "uplk-%s" % self.SERVICE_NAME
        NamedQueue(queue_name, **non_persistent_settings).delete()

    def _execute_update_callback(self, **kwargs):
        cur_time = now()
        blob_key = None
        update_type = kwargs.get('type', UpdaterType.NON_BLOCKING)
        blocking = kwargs.get('blocking', False)
        func = kwargs.get('func')
        update_execution_id = kwargs.get('id', uuid.uuid4().get_hex())
        ttl = kwargs.get('freq', UpdaterFrequency.MINUTE)
        if update_type == UpdaterType.BOX or update_type == UpdaterType.CLUSTER:
            blob_key = "UPD-%s" % self.SERVICE_NAME
            if update_type == UpdaterType.BOX:
                blob_key += "-%s" % self.mac.upper()
            last_update_time = self.result_store.get_blob(blob_key) or 0
            if cur_time < last_update_time + ttl:
                self.log.info("Skipping the update because the current time < last update time + update frequency.")
                return
            else:
                self.log.info("Service is ready to be updated (%s >= %s)" % (cur_time, last_update_time + ttl))

        if func is None:
            self.log.warning("_execute_update_callback was called with no callback function.")
            return

        if update_type == UpdaterType.BOX:
            if not self._lock_box_updater(update_execution_id, ttl):
                self.log.info("Did not get the updater lock. Some other process is taking care of the update.")
                return
        elif update_type == UpdaterType.CLUSTER:
            if not self._lock_cluster_updater(update_execution_id, ttl):
                self.log.info("Did not get the updater lock. Some other process is taking care of the update.")
                return

        if blocking:
            self.log.info("A blocking update is taking place (%s). "
                          "This will block processing for a while..." % update_execution_id)
            if update_type == UpdaterType.PROCESS:
                self._block_process_execution(update_execution_id, ttl)
            elif update_type == UpdaterType.BOX:
                self._block_box_execution(ttl)
            elif update_type == UpdaterType.CLUSTER:
                self.log.warning("Service '%s' is attempting a cluster execution block to update itself. "
                                 "This will pause all jobs that requested this service..." % self.SERVICE_NAME)
                self._block_cluster_execution(ttl)

        try:
            func(cfg=self.cfg)
        except Exception, e:
            self.log.exception("Updater id '%s' failed to run: %s" % (update_execution_id, e.message))
        finally:
            if update_type == UpdaterType.BOX:
                self._release_box_updater()
            elif update_type == UpdaterType.CLUSTER:
                self._release_cluster_updater()

            if blob_key:
                self.result_store.save_blob(blob_key, cur_time - 5)

            if blocking:
                if update_type == UpdaterType.PROCESS:
                    self._unblock_process_execution(update_execution_id)
                elif update_type == UpdaterType.BOX:
                    self._unblock_box_execution()
                elif update_type == UpdaterType.CLUSTER:
                    self._unblock_cluster_execution()

    def _get_config_key(self, task):
        if task.ignore_cache or self.SERVICE_DISABLE_CACHE:
            cfg = uuid.uuid4().get_hex()
        else:
            cfg = ''.join((
                str(get_service_overrides(task) or ''),
                str(self.get_config_data(task) or ''),
                str(self.get_tool_version() or ''),
                str(self.cfg or ''),
            ))

        if not cfg:
            return '0'

        return hashlib.md5(cfg).hexdigest()

    def _lookup_result_in_cache(self, task):
        task.from_cache = None
        if task.ignore_cache or self.SERVICE_DISABLE_CACHE:
            self.counters[CACHE_SKIPPED] += 1
            return task.from_cache
        cache_key, cached = self.result_store.lookup_result(
            self.SERVICE_NAME,
            self.get_service_version(),
            self._get_config_key(task),
            task.srl
        )
        cached_task = Task(cached or {})

        if cached:
            self.counters[CACHE_HIT] += 1
        else:
            self.counters[CACHE_MISS] += 1

        if (cached and
                self.submit_client.check_srls(cached_task.extracted_srls()) and
                self.submit_client.check_srls(cached_task.supplementary_srls())):
            self.result_store.freshen_result(self.SERVICE_NAME, self.get_service_version(), self._get_config_key(task),
                                             task.srl, cached, task.__expiry_ts__, task.classification)
            task.update_from_cached(cached)
            task.from_cache = cache_key
        return task.from_cache

    def _process_extracted_files(self, task):
        if not task.extracted:
            return

        hdr = task.submission.copy()
        hdr['psrl'] = task.srl
        hdr['depth'] = task.depth
        hdr['excluded'] = task.excluded
        hdr['selected'] = task.selected
        hdr['service_name'] = self.SERVICE_NAME
        self.log.info('%s Submitting Extracted: %s', self.SERVICE_NAME, task.sid)
        if task.from_cache:
            requests = task.extracted_requests()
            for k in requests:
                requests[k]['classification'] = Classification.max_classification(requests[k]['classification'],
                                                                                  task.classification)

            self.submit_client.submit_requests(requests, **hdr)  # pylint:disable=W0142
            return

        requests = task.extracted_files()
        for k in requests:
            requests[k]['classification'] = Classification.max_classification(requests[k]['classification'],
                                                                              task.classification)
        results = self.submit_client.submit_local_files(requests, **hdr)  # pylint:disable=W0142
        task.extracted = self._to_tuples(task.extracted, results)

    def _process_supplementary_files(self, task):
        if not task.supplementary:
            return

        if task.from_cache:
            return

        requests = task.supplementary_files()
        for k in requests:
            requests[k]['classification'] = Classification.max_classification(requests[k]['classification'],
                                                                              task.classification)
        results = self.submit_client.submit_supplementary_files(
            requests, location='far', ignore_size=True)
        task.supplementary = self._to_tuples(task.supplementary, results)

    def _register_update_callback(self, callback, blocking=False, execute_now=True,
                                  utype=UpdaterType.PROCESS, freq=UpdaterFrequency.HOUR):

        if self._updater is not None:
            raise ServiceDefinitionException("You can only register one update callback for now...")

        if not UpdaterType.is_valid(utype):
            raise ServiceDefinitionException("Invalid updater type: %s" % utype)

        if not UpdaterFrequency.is_valid(freq):
            raise ServiceDefinitionException("Invalid frequency (%s) can't update faster then each MINUTE." % freq)

        from apscheduler.scheduler import Scheduler

        self._updater = Scheduler()
        kwargs = {
            'func': callback,
            'type': utype,
            'freq': freq,
            'blocking': blocking,
            'id': uuid.uuid4().get_hex()
        }
        self.log.info("Registering update callback: %s" % str(kwargs))
        self._updater_id = kwargs['id']

        self._updater.add_interval_job(
            self._execute_update_callback,
            seconds=freq, kwargs=kwargs)

        if execute_now:
            self._execute_update_callback(**kwargs)

        self._updater.start()

    def _save_error(self, task):
        task.cache_key = self.result_store.save_error(
            self.SERVICE_NAME,
            self.get_service_version(),
            self._get_config_key(task),
            task
        )

    def _save_result(self, task):
        if task.from_cache:
            return task.from_cache

        if not task.save_result_flag:
            return None

        return self.result_store.save_result(
            self.SERVICE_NAME,
            self.get_service_version(),
            self._get_config_key(task),
            task.srl,
            task.classification,
            task.as_service_result()
        )

    def _send_dispatcher_ack(self, task):
        self.dispatch_queue.send_raw(task.as_dispatcher_ack(self.service_timeout))

    def _send_dispatcher_response(self, task):
        self.dispatch_queue.send_raw(task.as_dispatcher_response())

    def _success(self, task):
        if task.result:
            tags = task.result.get('tags', None) or []
            if tags:
                ExpiringSet(task.get_tag_set_name()).add(*tags)

        self._process_extracted_files(task)
        self._process_supplementary_files(task)
        self._ensure_size_constraints(task)

        cache_key = self._save_result(task)

        task.success()

        task.cache_key = cache_key

    # noinspection PyBroadException
    def _to_tuples(self, children, results):
        # NOTE: Convert children to tuples.
        rid = -1
        tuples = []
        for child in children:
            rid += 1

            try:
                os.remove(child.path)
            except OSError, e:  # pylint:disable=W0702
                if e.errno == 2:
                    pass
                else:
                    self.log.exception('Problem cleaning up file: %s' % safe_str(child.path))

            try:
                result = results.get(str(rid), {})

                if result and result.get('succeeded', True):
                    srl = Task(result).srl or Task(result).sha256 or result.get('sha256', None)
                    tuples.append(child.as_tuple(srl, self.normalize_path))
            except:  # pylint:disable=W0702
                self.log.exception('Problem matching request/response for children')

        return tuples

    # noinspection PyBroadException
    def _cleanup_working_directory(self):
        try:
            if self._working_directory:
                shutil.rmtree(self._working_directory)
                self._working_directory = None
        except:  # pylint: disable=W0702
            self.log.warn('Could not remove working directory: %s',
                          self._working_directory)

    # noinspection PyBroadException
    def _log_completion_record(self, task, duration):
        if task.score >= 0:
            self.counters[JOB_SCORED] += 1
        else:
            self.counters[JOB_NOT_SCORED] += 1

        # We are temporarily logging the size of the raw result for investigation.
        try:
            length = len(json.dumps(task.as_service_result()))
        except:  # pylint:disable=W0702
            length = -1

        self.log.info('Done:  %s/%s C:%s S:%s T:%.3f Z:%s L:%s',
                      task.sid, task.srl,
                      1 if task.from_cache else 0,
                      task.score or 0,
                      duration,
                      task.size,
                      length)

    def _handle_execute_failure(self, task, exception, stack_info):
        # Get rid of result in case it was what caused the problem.
        task.result = None
        # Also get rid of extracted and supplementary.
        task.clear_extracted()
        task.clear_supplementary()
        if isinstance(exception, exceptions.RecoverableError):
            self.log.info('Recoverable Service Error (%s/%s) %s: %s', task.sid, task.srl, exception, stack_info)
            self.counters[EXECUTE_FAIL_RECOV] += 1
            task.recoverable_failure(stack_info)
        else:
            self.log.error('Service Error (%s/%s) %s: %s', task.sid, task.srl, exception, stack_info)
            self.counters[EXECUTE_FAIL_NONRECOV] += 1
            task.nonrecoverable_failure(stack_info)
        self._save_error(task)

    # noinspection PyBroadException
    def _ensure_size_constraints(self, task):

        if not task or not task.result:
            return

        try:
            max_result_size = 1024 * 512
            serialized = json.dumps(task.as_service_result())
            if len(serialized) <= max_result_size:
                return

            self.log.info("result is oversized. shrinking. (%s)", len(serialized))
            # Remove the tags and sections, leaving the score and tag_score intact.
            # Submit the oversized result as supplementary file.
            task.result['tags'] = []
            filename = '_'.join([self.SERVICE_NAME, task.srl, 'result.json'])
            result_path = os.path.join(self.working_directory, filename)
            with open(result_path, 'w') as f:
                f.write(serialized)

            # upload the oversized result as a supplementary file.
            results = self.submit_client.submit_supplementary_files(
                {'0': {'path': result_path}}, location='far',
                classification=task.result['classification'],
                ignore_size=True)
            task.supplementary.extend(self._to_tuples(
                [Child(result_path, 'oversized result')], results))

            oversize_notice_section = ResultSection(
                title_text='Result exceeded max size. Attached as supplementary file. Score has been preserved.')
            task.result['sections'] = [json.loads(json.dumps(oversize_notice_section))]
        except:  # pylint:disable=W0702
            self.log.exception("while shrinking oversized result")

    def _handle_task(self, task):
        self._block_for_updater()
        self.counters[EXECUTE_START] += 1
        task_age = self.get_task_age(task)
        self.log.info('Start: %s/%s (%s)[p%s] AGE:%s', task.sid, task.srl, task.tag, task.priority, task_age)
        task.watermark(self.SERVICE_NAME, self.get_service_version())
        task.save_result_flag = self.SERVICE_SAVE_RESULT
        task.service_debug_info = "serviced_on:%s" % self._ip
        self._send_dispatcher_ack(task)

        try:
            start_time = time.time()
            # First try to fetch from cache. If that misses,
            # run the service execute to get a fresh result.
            if not self._lookup_result_in_cache(task):
                task.clear_extracted()
                task.clear_supplementary()
                # Pass it to the service for processing. Wrap it in ServiceRequest
                # facade so service writers don't see a request interface with 80 members.
                request = ServiceRequest(self, task)

                # Collect submission_tags
                if task.is_initial():
                    self.submission_tags = {}
                else:
                    self.submission_tags = ExpiringHash(task.get_submission_tags_name()).items()

                old_result = self.execute(request)
                if old_result:
                    self.log.warning("Service %s is using old convention "
                                     "returning result instead of setting "
                                     "it in request", self.SERVICE_NAME)
                    task.result = old_result
                elif task.save_result_flag and not task.result:
                    self.log.info("Service %s supplied NO result at all. Creating empty result for the service...",
                                  self.SERVICE_NAME)
                    task.result = Result()

                task.milestones = {'service_started': start_time, 'service_completed': time.time()}
                if task.save_result_flag:
                    task.result.finalize()

            self._success(task)
            self._log_completion_record(task, (time.time() - start_time))
        except Exception as ex:  # pylint:disable=W0703
            self._handle_execute_failure(task, ex, exceptions.get_stacktrace_info(ex))
            if not isinstance(ex, exceptions.RecoverableError):
                self.log.exception("While processing task: %s/%s", task.sid, task.srl)
                raise
            else:
                self.log.info("While processing task: %s/%s", task.sid, task.srl)
        finally:
            self._send_dispatcher_response(task)
            self._cleanup_working_directory()
            self.counters[EXECUTE_DONE] += 1

    def normalize_path(self, path):
        return path.replace(os.path.join(self.working_directory, ''), '', 1)

    # noinspection PyBroadException
    def start_service(self):
        # Start this service. Common service start is performed and then
        # the derived services start() is invoked.
        # Services should perform any pre-fork (once per celery app) init
        # in the constructor. Any init/config that is not fork-safe or is
        # otherwise subprocess specific should be done here.

        try:
            self._ip = net.get_hostip()
        except:  # pylint:disable=W0702
            pass
        self.counters = Counters()
        self.counters['name'] = self.SERVICE_NAME
        self.counters['type'] = "service"
        self.counters['host'] = self._ip
        self.transport = forge.get_filestore()
        self.result_store = forge.get_datastore()
        self.submit_client = forge.get_submit_client(self.result_store)
        self.dispatch_queue = forge.get_dispatch_queue()
        self.log.info('Service Starting: %s', self.SERVICE_NAME)

        # Tell the service to do its service specific imports.
        # We pop the CWD from the module search path to avoid
        # namespace collisions.
        cwd_save = sys.path.pop(0)
        self.import_service_deps()
        sys.path.insert(0, cwd_save)

        self.start()
        if self.SERVICE_SAFE_START:
            NamedQueue('safe-start-%s' % self.mac).push('up')

    @property
    def should_run(self):
        # For sysprep we're not actually instantiated by the worker,
        # so make sure we have a reference to our creator.
        if self.worker and self.worker.should_run:
            return self.worker.should_run.value
        return True

    def stop_service(self):
        # Perform common stop routines and then invoke the child's stop().
        self.log.info('Service Stopping: %s', self.SERVICE_NAME)
        self.stop()
        # self._cleanup_working_directory()

    @property
    def service_timeout(self):
        # Services may wish to override this with more complicated logic.
        return self.cfg.get('timeout', self.SERVICE_TIMEOUT)

    @property
    def source_directory(self):
        return modulepath(self.__class__.__module__)

    @property
    def working_directory(self):
        pid = os.getpid()
        al_temp_dir = os.path.join(tempfile.gettempdir(), 'al', self.SERVICE_NAME, str(pid))
        if not os.path.isdir(al_temp_dir):
            os.makedirs(al_temp_dir)
        if self._working_directory is None:
            self._working_directory = tempfile.mkdtemp(dir=al_temp_dir)
        return self._working_directory

    # noinspection PyPep8Naming,PyNestedDecorators
    @classproperty
    @classmethod
    def SERVICE_NAME(cls):  # pylint:disable=C0103
        return cls.__name__

    @classmethod
    def get_default_config(cls):
        return {
            'accepts': cls.SERVICE_ACCEPTS,
            'category': cls.SERVICE_CATEGORY,
            'classpath': '.'.join((cls.__module__, cls.SERVICE_NAME)),
            'config': cls.SERVICE_DEFAULT_CONFIG,
            'cpu_cores': cls.SERVICE_CPU_CORES,
            'description': cls.SERVICE_DESCRIPTION,
            'enabled': cls.SERVICE_ENABLED,
            'name': cls.SERVICE_NAME,
            'ram_mb': cls.SERVICE_RAM_MB,
            'rejects': cls.SERVICE_REJECTS,
            'stage': cls.SERVICE_STAGE,
            'submission_params': cls.SERVICE_DEFAULT_SUBMISSION_PARAMS,
            'supported_platforms': cls.SERVICE_SUPPORTED_PLATFORMS,
            'timeout': cls.SERVICE_TIMEOUT,
            'is_external': cls.SERVICE_IS_EXTERNAL
        }

    @classmethod
    def get_service_version(cls):
        t = (
            version.SYSTEM_VERSION,
            version.FRAMEWORK_VERSION,
            cls.SERVICE_VERSION,
            cls.SERVICE_REVISION,
        )
        return '.'.join([str(v) for v in t])

    # noinspection PyBroadException
    @staticmethod
    def parse_revision(revision):
        try:
            return revision.strip('$').split(':')[1].strip()[:7]
        except:  # pylint:disable=W0702
            return '0'

    # noinspection PyBroadException
    def _register_cleanup_op(self, op):
        try:
            queue_name = "cleanup-%s" % self.mac
            NamedQueue(queue_name, **persistent_settings).push(op)
            self.log.info("Registered cleanup operation: %s", str(op))
        except:  # pylint: disable=W0702
            self.log.exception("Unable to register cleanup operation!: ")


class BatchServiceBase(ServiceBase):  # pylint:disable=R0921
    BATCH_SERVICE = True
    BATCH_SIZE = 50
    BATCH_TIMEOUT_SECS = 3

    SUPPORTS_SRBATCH = False

    def _download_batch(self, tasks, dest_dir=None):
        succeeded = {}
        failed = []
        if dest_dir is None:
            dest_dir = self.working_directory

        for task in tasks:
            try:
                local_path = os.path.join(dest_dir, os.path.basename(task.srl))
                self.transport.download(task.srl, local_path)
                succeeded[local_path] = task
            except Exception as ex:  # pylint: disable=W0703
                failed.append((task, ex))
                msg = exceptions.get_stacktrace_info(ex)
                task.nonrecoverable_failure(msg)
                self._save_error(task)
                self._send_dispatcher_response(task)
        return succeeded, failed

    # noinspection PyBroadException
    def _delete_downloaded_batch(self, tasks, dest_dir=None):
        succeeded = []
        failed = []
        if dest_dir is None:
            dest_dir = self.working_directory

        for task in tasks:
            try:
                local_path = os.path.join(dest_dir, os.path.basename(task.srl))
                os.unlink(local_path)
                succeeded.append(local_path)
            except:  # pylint:disable=W0702
                self.log.exception('Failed to remove downloaded file: %s', local_path)
                failed.append(local_path)
        return succeeded, failed

    def _fail_all_in_batch(self, task_batch, msg, recoverable=True):
        for task in task_batch:
            if recoverable:
                task.recoverable_failure(msg)
            else:
                task.nonrecoverable_failure(msg)
            self._save_error(task)
            self._send_dispatcher_response(task)

    def _finalize(self, task, duration, batch_size):
        task.service_debug_info = "serviced_on:%s" % self._ip
        if task.save_result_flag:
            task.result.finalize()
        self._log_completion_record(task, (duration / batch_size))
        self._success(task)
        self._send_dispatcher_response(task)

    def _process_cached_task(self, task):
        start = time.time()
        if not self._lookup_result_in_cache(task):
            return task

        task.save_result_flag = self.SERVICE_SAVE_RESULT
        self._log_completion_record(task, (time.time() - start))
        self._success(task)
        self._send_dispatcher_response(task)

        return None

    def execute(self, _task):
        raise Exception('execute() called on a batch service. Expected execute_batch().')

    def execute_batch(self, _batch):
        raise NotImplementedError('execute_batch() not implemented in BatchService.')

    def _handle_task_batch(self, tasks):
        """ Handle a batch of tasks at once.
        Argument: A list of Task objects
        """
        # Expedite any tasks with cached results.
        self._block_for_updater()
        start_time = time.time()
        num_tasks = len(tasks)
        self.log.info('StartBatch: %s', num_tasks)
        self.counters[EXECUTE_START] += num_tasks

        for task in tasks:
            task.watermark(self.SERVICE_NAME, self.get_service_version())
            task.save_result_flag = self.SERVICE_SAVE_RESULT
            self._send_dispatcher_ack(task)

        plan = [(self._process_cached_task, (task,), tid) for tid, task in enumerate(tasks)]
        result = execute_concurrently(plan)
        if '_exception_' in result:
            failed = result.pop('_exception_')
            self.log.error("Exception in concurrent execution: %s", str(failed))

        cache_misses = [cache_miss for cache_miss in result.itervalues() if cache_miss]

        self.log.info("Cache status: H:%s M:%s" % (len(tasks) - len(cache_misses), len(cache_misses)))

        successful = []
        try:
            # execute_batch will assign the results to each task in place.
            # and is also responsible for setting success or failure state.
            if not cache_misses:
                self.log.info("No tasks left after cache interrogation")
            elif self.SUPPORTS_SRBATCH:
                batch = ServiceRequestBatch(self, cache_misses)
                self.execute_batch(batch)
                for request in batch.requests:
                    if request.successful:
                        request.error_text = ''
                        successful.append(request.task)
                    else:
                        if request.error_is_recoverable:
                            self._handle_execute_failure(request.task,
                                                         exceptions.RecoverableError(request.error_text),
                                                         request.error_text)
                        else:
                            self._handle_execute_failure(request.task,
                                                         exceptions.NonRecoverableError(request.error_text),
                                                         request.error_text)
                        self._send_dispatcher_response(request.task)

            else:
                self.execute_batch(cache_misses)
                successful.extend(cache_misses)
        except Exception as ex:  # pylint:disable=W0703
            self.log.exception('While processing batch of size %s. Failing all.', len(cache_misses))
            msg = exceptions.get_stacktrace_info(ex)
            self._fail_all_in_batch(cache_misses, msg, recoverable=False)
            self._cleanup_working_directory()
            self.counters[EXECUTE_DONE] += num_tasks
            return

        duration = time.time() - start_time
        self.log.info('DoneBatch: %s. T:%s', len(tasks), duration)

        if len(successful) > 0:
            plan = [(self._finalize, (task, duration, len(tasks)), tid) for tid, task in enumerate(successful)]
            execute_concurrently(plan)

        self._cleanup_working_directory()
        self.counters[EXECUTE_DONE] += num_tasks


def skip_low_scoring(task, threshold=0):
    if task.deep_scan:
        skip = False
    else:
        skip = task.max_score <= threshold

    if skip:
        task.save_result_flag = False

    return skip


def skip_probabilistic(task):
    if task.deep_scan:
        skip = False
    elif task.max_score < 0 or 500 <= task.max_score:
        skip = True
    else:
        # Scan:
        # 0.001% with a score of 0 (scan with probability 1 / 10^5)
        # 0.01% with a score between 1 and 100
        # 0.1% with a score between 101 and 200
        # 1% with a score between 201 and 300
        # 10% with a score between 301 and 400
        # 100% with a score between 401 and 400
        scan_probability = 1.0 / 10 ** ((500 - task.max_score) / 100)

        # The function random returns a float in the range [0, 1).
        skip = random() >= scan_probability

    if skip:
        task.save_result_flag = False

    return skip