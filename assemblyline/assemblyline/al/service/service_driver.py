"""
  ServiceDriver

  ServiceDriver manages the tasks and processes associate with a single 'type' of service (e.g. Yara).

  There is a ServiceDriver instantiated for each type of service running on a node. The driver
  is responsible for launching 'ServiceWorker's which are the subprocesses that actually perform the work.

  The ServiceDriver aims to keep a preconfigured number of ServiceWorkers running at all times. If a worker dies or
  appears to be stuck the driver will kill it and spawn a new ServiceWorker to take it's place.

  The ServiceDriver may 'retire' a ServiceWorker if it has been running for an exceptionally long
  time or has processed a large number of records or has failed too many times consecutively.

  The ServiceDriver has 1 housekeeping/supervisor thread that monitors the ServiceWorkers. Each ServiceWorker is a
  subprocess (multiprocessing.Process).


  CAVEATS/IMPLEMENTATION NOTES:

  Due to the way Python implements fork() on Windows, ServiceWorker should never instantiate non trivial
  members in its constructor. Instead defer this to _run_service(). Python pickles the ServiceWorker
  at runtime as part of its fork implementation. If any non pickleable members are in ServiceWorker
  at that time, subprocessing will break.

  multiprocessing.Value's are used to share values between the parent and child processes. Any access to one of these
  members can be considered to be via shared memory between parent and child.

  Python signal handling notes: By default an INT signal sent to the parent will cause a KeyboardInterrupt to
  spontaneously occur at any line of code in any/all children. To avoid this, we disable signals in the children and
  instead have them monitor a 'should_run' variable. Only the parent will get the Interrupt and it will toggle this
  value for all children.
"""


from __future__ import absolute_import

import logging
import os
import platform
import shutil
import signal
import tempfile
import threading

from assemblyline.al.common import forge
from assemblyline.al.common import log
from multiprocessing import Process, Value
from Queue import Empty
from assemblyline.common.process import try_setproctitle
from assemblyline.al.common.task import Task
from time import sleep, time


IDLE = 0.0                # Special value to indicate worker is not currently processing.
SOFT_STOP_TTL = 10        # Give worker this much time to come down clean before terminate().

# ServiceWorker exit codes.
EXIT_OK = 0
EXIT_INTERRUPTED = 1
EXIT_FAIL_UNKNOWN = 2
EXIT_OK_OLDAGE = 10
EXIT_FAIL_TOO_MANY = 9
EXIT_FAIL_START = 3
EXIT_FAIL_PROCESSING = 4
EXIT_FAIL_INSTANTIATE = 5


class ServiceWorker(Process):
    """ A ServiceWorker is a child processes that consume work from the drivers shared work queue and complete
        the work with the service it represents.

        The ServiceWorkers are forked child processes. A 'ServiceDriver' launches and tracks each worker.
        Keep in mind that when calling methods on ServiceWorker from the ServiceDriver you are accessing the
        pre-fork ServiceWorker from the parent process context.  The only state changes child will notice
        from this context changes to multiprocessing.Value's, multiprocessing.Queue's.
     """

    # context: prefork
    def __init__(self, service_cls, service_config, config_overrides=None):
        """
         WARN WARN WARN
         Do not initialize any non pickleable member variables in __init__.
         Otherwise, process creation will fail on windows.  Try to initialize
         non POD objects at the start of run_service instead. This method is called after
         the fork().
        """
        super(ServiceWorker, self).__init__(target=self.subprocess_entry_point)
        self.config = service_config
        self.config_overrides = config_overrides

        # last_work_started shared with forked process via shared memory.
        self.should_run = Value('i', 1)
        self.last_work_started = Value('d', 0.0)
        self.last_work_started.value = IDLE
        self.work_count = Value('i', 0)

        self.service_cls = service_cls
        self.logname = 'assemblyline.svc.worker.%s' % self.service_cls.SERVICE_NAME.lower()

        # These are non-pickleable, instantiation is deferred to run_service().
        self.service = None
        self.log = None
        self.ingest_queue = None
        self.work_batch = []
        self.batch_started = 0

        self._supervisor_thread = None

        # Worker keeps track of the current work item (or items for batch)
        # so that it can fail them if the service becomes unresponsive or crashes.
        self._current_work_items_lock = None
        self._current_work_items = []

        self._stats_sink = None

    # context: prefork
    def get_stats(self):
        """ Return a statistics dictionary regarding state of this worker. """

        hb = {'revision': self.service_cls.SERVICE_REVISION}
        return hb

    # context: prefork
    def stop_soft(self):
        """ Tell the worker it should shut down.

        The worker checks this value in between work items so it may take a moment before it starts
        to actually stop. It will not interrupt work in progress. Use stop_hard if you need a guarantee
        that the worker is stopped.
        """

        self.should_run.value = 0

    # context: prefork
    def stop_hard(self, time_to_stop=SOFT_STOP_TTL):
        """ Tell the worker to stop and terminate() it if it doesn't after timeout provided.

        The worker will be told to stop. If it doesnt stop cleanly/softly in the time specified,
        it will be terminated. We should endeavour to never have to terminate() a process as
        that can leave sockets/fd/shared resources etc in an unknown state.
        """
        cur_log = logging.getLogger(self.logname)
        self.should_run.value = 0
        for second in range(0, time_to_stop):
            if not self.is_alive():
                cur_log.info('stopped softly.')
                return
            cur_log.info('waiting to come down softly. %s (%s). last_work_started: %s. now: %s',
                         SOFT_STOP_TTL - second, self.pid, self.last_work_started.value, time())
            sleep(0.5)

        cur_log.info('did not stop softly in time. terminating.')
        self.terminate()

    # context: prefork
    def busy_for_more_than(self, time_allowed):
        """ Check if this worker has been busy (working on the same task)

        When the worker starts a task it will set a shared memory value with the current time.
        When it finishes a task it sets that value back to a magic constant 'IDLE'.
        This allows the parent to detect 'stuck' workers.
        """

        last_started = self.last_work_started.value  # save to local stack. it is volatile
        if last_started == IDLE:
            return False

        cur_log = logging.getLogger(self.logname)
        busy_for = time() - last_started
        cur_log.debug('%s busy_for: %s', self.service_cls.SERVICE_NAME, busy_for)
        if busy_for > time_allowed:
            cur_log.info('busy for a while. started: %s - now: %s timeout: %s',
                         last_started, time(), time_allowed)
        return busy_for > time_allowed

    # context: postfork
    def _fetch_work(self, timeout=0.5):
        """ Fetch a single work item from our work queue.
        Return None if no work is available after timeout seconds.
        """
        work = None
        try:
            work_tuple = self.ingest_queue.pop()
            if not work_tuple:
                sleep(timeout)
            else:
                work = work_tuple[0]
        except Empty:
            pass

        return work

    # context: postfork
    def _do_work(self, raw_task):
        """ Complete an incoming work item.

        Note: This will block while a service is executing the task.
        For some services this could be many seconds or even minutes.
        """
        assert not isinstance(raw_task, list)
        task = Task(raw_task)
        # noinspection PyProtectedMember
        self.service._handle_task(task)
        self.work_count.value += 1

    def _save_current_work(self, work):
        with self._current_work_items_lock:
            if not isinstance(work, list):
                self._current_work_items = [work, ]
            else:
                self._current_work_items = work

    def _clear_current_work(self):
        with self._current_work_items_lock:
            self._current_work_items = []

    # context: postfork
    def _work_until_death(self):
        """ Complete work until shutdown is indicated.

        This will continuously consume work from the shared work queue and
        complete it until shutdown is indicated.

        If too many work items fail consecutively, this worker will terminate itself.
        This will cause the driver to spawn a new replacement worker.

        The return value of will become the exit code of the process.
        """
        tasks_completed = 0
        consecutive_failures = 0
        exit_code = EXIT_FAIL_UNKNOWN
        # noinspection PyBroadException
        try:
            while self.should_run.value:
                work = self._fetch_work()  # blocks 0.5s on no work.
                if not work:
                    continue

                # noinspection PyBroadException
                try:
                    self.last_work_started.value = time()
                    self._save_current_work(work)  # for supervisor thread
                    self._do_work(work)
                    self._clear_current_work()
                    consecutive_failures = 0
                    tasks_completed += 1
                except:
                    consecutive_failures += 1
                    self.log.exception('Exception during Service Execute. Consecutive Failures: %s',
                                       consecutive_failures)
                finally:
                    self.last_work_started.value = IDLE

                if consecutive_failures > 20:
                    self.log.error('Exceeded max consecutive failures. Committing Seppuka.')
                    self.should_run.value = 0
                    exit_code = EXIT_FAIL_TOO_MANY

                if tasks_completed > 10000:
                    self.log.info('Reached task completion threshold. Exiting to allow new worker to spawn.')
                    self.should_run.value = 0
                    exit_code = EXIT_OK_OLDAGE
        except KeyboardInterrupt:
            # Technically we should never see this as we mask signals right after the fork.
            raise
        except:
            self.log.exception("Worker terminated abnormally.")
            exit_code = EXIT_FAIL_UNKNOWN

        return exit_code

    # context: postfork
    def subprocess_entry_point(self):
        """ The Worker's initial entry point after being spawned."""
        # Ignore signal.SIGINT. Let parent handle it and let us know when to stop via self.should_run.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        try:
            if platform.system() == 'Windows':
                # log init doesn't servive the 'fork' on windows. redo.
                log.init_logging('hostagent')

            # Name our process after the service type. Makes 'ps' listings easier to read.
            try_setproctitle(self.service_cls.SERVICE_NAME)
            self.log = logging.getLogger('assemblyline.svc.worker.%s' % self.service_cls.SERVICE_NAME.lower())

            msgs = forge.apply_overrides(self.config_overrides)
            if msgs:
                self.log.info("Using %s.", " and ".join(msgs))

            self.ingest_queue = forge.get_service_queue(self.service_cls.SERVICE_NAME)  # remote job queue.
            self._stats_sink = forge.get_metrics_sink()

            self.log.info("Instantiating supervisor thread")

            self._current_work_items_lock = threading.Lock()
            self._supervisor_thread = threading.Thread(name='service-drainer', target=self._supervisor_thread_main)
            self._supervisor_thread.start()

            self.log.info("Supervisor thread instantiated")

            self._run_service_until_shutdown()

            self.log.info('_run_service has exited. we must be stopping')
        except KeyboardInterrupt:
            self.should_run = False
            # This should happen if the signal.signal call above is working as expected.
            return EXIT_INTERRUPTED

    # context: postfork supervisor thread
    def _drain(self):

        with self._current_work_items_lock:
            if not self._current_work_items:
                self.log.info('EXIT_DRAIN:0')
                return

            result_store = forge.get_datastore()
            dispatch_queue = forge.get_dispatch_queue()
            self.log.info('EXIT_DRAIN:%s', len(self._current_work_items))
            for item in self._current_work_items:
                work = Task(item)
                task = Task({})
                task.sid = work.sid
                task.srl = work.srl
                task.dispatch_queue = work.dispatch_queue
                task.classification = work.classification
                self.log.info("DRAIN: %s/%s", task.sid, task.srl)
                task.watermark(self.service_cls.SERVICE_NAME, None)
                task.recoverable_failure('Task was pre-empted (shutdown, vm revert or cull)')
                task.cache_key = result_store.save_error(self.service_cls.SERVICE_NAME, None, None, task)
                dispatch_queue.send_raw(task.as_dispatcher_response())

    # context: postfork supervisor thread
    def _supervisor_thread_main(self):

        # noinspection PyBroadException
        try:
            tick = 0
            while self.should_run.value:
                sleep(0.5)
                # noinspection PyBroadException
                try:
                    if self._stats_sink and self.service and tick % 5 == 0:
                        self._stats_sink.publish(self.service.get_counters())
                except:
                    self.log.exception('could not push stats')
                tick += 0.5
            self._drain()
        except:
            self.log.exception('In supervisor thread.')

        return

    # context: postfork
    def _run_service_until_shutdown(self):
        """ Instantiate our service and have it complete work until shutdown."""

        # Instantiate the service object.
        # noinspection PyBroadException
        try:
            self.service = self.service_cls(self.config)
            self.service.worker = self
        except:
            self.log.exception('Failed to instantiate service: %s.', self.service_cls.__name__)
            return EXIT_FAIL_INSTANTIATE

        # Start the service.
        # noinspection PyBroadException
        try:
            self.service.start_service()
            self.log.info("Service started within this worker %s.", self.service_cls.SERVICE_NAME)
        except:
            self.log.exception('Failed to start service: %s.', self.service_cls.__name__)
            return EXIT_FAIL_START

        # Have the service work until we are shutdown.
        exit_code = self._work_until_death()

        # Stop the underlying service (best effort).
        # noinspection PyBroadException
        try:
            self.service.stop_service()
        except:
            self.log.exception("Service could not be stopped cleanly.")

        return exit_code


class BatchServiceWorker(ServiceWorker):
    """ In batch mode the driver will collect multiple tasks into a single queue item
    then place that batch on the shared work queue. This way a single worker will pop
    off the entire batch in an atomic operation and we can keep the rest of the worker code
    the same."""

    def __init__(self, service_cls, service_config, config_overrides=None):
        super(BatchServiceWorker, self).__init__(service_cls, service_config, config_overrides)
        self.batch_started = 0
        self.batched_work = []

    def _fetch_work(self, timeout=0.5):
        """ Fetch a single work item from our work queue.

        Return None if no work is available after timeout seconds.
        """
        work = []
        batch_size = self.service_cls.BATCH_SIZE
        seconds_remaining = self.service_cls.BATCH_TIMEOUT_SECS

        while (self.should_run.value and
               (len(work) < batch_size) and
               (seconds_remaining > 0)):
            try:
                work_tuple = self.ingest_queue.pop()
                if not work_tuple:
                    sleep(1)
                    seconds_remaining -= 1
                    continue

                work_item = work_tuple[0]
                work.append(work_item)
            except Empty:
                pass
        return work

    def _do_work(self, work):
        tasks = [Task(raw) for raw in work]
        # noinspection PyProtectedMember
        self.service._handle_task_batch(tasks)


class ServiceDriver(object):
    """ Launch and track Workers to process jobs for a specific type of service.

    There is typically 1 ServiceDriver per 'type' of service.
    The driver is responsible for fetching work from the remote job queue, and launching and tracking
    ServiceWorkers (child processes).
    """

    def __init__(self, service_cls, cfg, service_timeout, num_workers=3, config_overrides=None):
        """ The ServiceDriver is constructed in a dormant state.
            Call start() when it should start processing. """
        self.workers = []
        self.graveyard = []  # previous (now dead) worker pids (for debugging).
        self.cfg = cfg
        self.config_overrides = config_overrides
        self.service_cls = service_cls
        self.desired_num_workers = num_workers
        self.batch_mode = service_cls.BATCH_SERVICE
        self.worker_cls = BatchServiceWorker if self.batch_mode else ServiceWorker
        self.should_run = True
        self.supervisor_thread = threading.Thread(target=self.supervisor_thread_main)
        self.driver_lock = threading.Lock()
        self.service_timeout = service_timeout
        self.log = logging.getLogger('assemblyline.svc.driver.%s' % self.service_cls.SERVICE_NAME.lower())

    def get_stats(self):
        """ Return a statistics dictionary regarding the state of this driver. """
        stats = {
            'name': self.get_name(),
            'num_workers': self.desired_num_workers,
        }

        # Add a section for each worker currently running.
        worker_stats = {}
        for worker in self.workers:
            worker_stats[worker.pid] = worker.get_stats()

        stats['workers'] = worker_stats
        return stats

    def get_name(self):
        """ Return name of this driver (currently same as Service Name)."""
        return self.service_cls.SERVICE_NAME

    def start(self):
        """ Start the driver.
        This will launch the worker processes and start the supervisor thread.
        It is non blocking. Call stop_soft and/or stop_hard to stop the driver.
        """
        self.log.info("Starting Driver: %s" % self.service_cls.SERVICE_NAME)
        with self.driver_lock:
            temp_dir = None
            # noinspection PyBroadException
            try:
                temp_dir = os.path.join(tempfile.gettempdir(), 'al', self.service_cls.SERVICE_NAME)
                self.log.info("Wiping existing working directory: " + temp_dir)
                if os.path.isdir(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                if temp_dir:
                    self.log.error("Failed to clean up working directory: " + temp_dir)
            # Before we launch a bevy or workers. create a single one and invoke sysprep
            # on it to allow for one time setup.
            # noinspection PyBroadException
            try:
                _sysprep_instance = self.service_cls(self.cfg)
                _sysprep_instance.sysprep() 
            except:
                self.log.exception("during service sysprep")

            # not start the actual workers.
            self.workers = self._create_start_n_workers(self.desired_num_workers)
            self.supervisor_thread.start()
        self.log.info("Driver Started: %s" % self.service_cls.SERVICE_NAME)

    def stop_supervisor(self):
        """ Stop only the supervisor thread.

        This is provided as a speedup convenience method to allow ServiceManager
        to stop multiple drivers simultaneously faster. Since we need to stop and join
        the supervisor thread before we can stop the workers we allow the servicemanager
        to do a pass over all the drivers and begin the supervisor thread stop. It can
        then do a second pass over the drivers and call stop_soft or stop_hard and not have
        to block so long while each one shuts down.
        """
        self.should_run = False

    def stop_soft(self):
        """ Ensure supervisor thread is stopped and stop all workers.

        Note: stop_soft only instructs the wokers to shutdown. It does not block or join
        to see that they are stopped.  call stop_hard if you need this gaurantee.
        Typically ServiceManager wants to stop multiple drivers at the same time so
        it will do one pass over all drivers calling stop_soft then a second pass over them
        with stop_hard. This makes for faster bulk shutdown.
        """
        self.should_run = False
        self.supervisor_thread.join(3)
        if self.supervisor_thread.isAlive():
            self.log.error("supervisor thread has still not shutdown")
        # We only need this lock if supervisor thread is still running.
        # If we ever start deadlocking we can look into removing it.
        with self.driver_lock:
            _ = [w.stop_soft() for w in self.workers]

    def stop_hard(self, soft_stop_timeout=10):
        """ Stop this driver and ensure all workers are down.
        If workers do not come down cleanly in timeout provided, they will be terminated.
        """
        self.should_run = False
        try:
            with self.driver_lock:
                self.supervisor_thread.join(5.0)
                if self.supervisor_thread.is_alive():
                    self.log.error('supervisor thread may not have terminated.')

                _ = [w.stop_hard(soft_stop_timeout) for w in self.workers]
                _ = [w.join(2) for w in self.workers]  # Note: Should we be joining terminated processes?

                for w in self.workers:
                    if w.is_alive():
                        self.log.warn('Worker subprocess is still alive after stop_hard.')

        except KeyboardInterrupt:
            self.log.error('Got another CTRL-C during shutdown. Termination unclean.')
            raise

    def supervisor_thread_main(self):
        """ Entry point for the driver's supervisor thread.

        The supervisor thread is responsible for checking the health of the workers
        and spawning/killing workers as necessary.
        """
        self.log.info('Primary Thread Starting for %s', self.service_cls.SERVICE_NAME)
        tick_count = 0
        check_worker_period = 30
        # noinspection PyBroadException
        try:
            while self.should_run:
                tick_count += 1
                if tick_count % check_worker_period == 0:
                    with self.driver_lock:
                        self._check_cull_workers()
                    sleep(1)
        except KeyboardInterrupt:
            self.should_run = False
        except:
            self.log.exception('In supervisor_thread_main.')
        self.log.info('Primary Thread Exiting')

    def _check_cull_workers(self):
        """ Check the health of all workers and cull as necessary.

        Any dead workers will be replaced with new ones.
        Any workers that have not made forward process in a long time will
        be assumed to be 'stuck' and will be culled/replaced.
        """
        deceased = filter(lambda x: not x.is_alive(), self.workers)
        if deceased:
            # Track the dead for now (debugging/testing).
            dead_pids = [str(d.pid) for d in deceased]
            self.graveyard.extend(dead_pids)

            # Prune the dead out of workers list. Replace them with fresh workers.
            self.workers = filter(lambda x: x.is_alive(), self.workers)
            self._log_checkresult(dead_pids)
            # noinspection PyTypeChecker
            self.workers.extend(self._create_start_n_workers(len(dead_pids)))
            assert len(self.workers) == self.desired_num_workers

        # Check for hung processes
        for w in self.workers:
            if w.busy_for_more_than(self.service_timeout):
                self.log.info("check_cull: %s appears to be stuck on a work item. culling.", w.pid)
                # noinspection PyBroadException
                try:
                    w.stop_hard()
                except:
                    self.log.exception("check_cull: %s did not come down cleanly." % w.pid)

    def _log_checkresult(self, dead_pids):
        """ Log a status message regarding state of workers (past and present). """
        self.log.info('starting %s new workers to replace the dead (%s). Graveyard:[%s]',
                      len(dead_pids),
                      ','.join(dead_pids),
                      ','.join(self.graveyard))

    def _create_start_n_workers(self, num_to_create):
        """ Create and start the number of workers specified.

        Returns: list of the workers started.
        """
        new_workers = [
            self.worker_cls(
                self.service_cls,
                self.cfg,
                self.config_overrides) for _ in range(0, num_to_create)]

        _ = [w.start() for w in new_workers]
        return new_workers
