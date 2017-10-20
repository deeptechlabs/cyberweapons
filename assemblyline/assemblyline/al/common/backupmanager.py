
import json
import time
import os
import subprocess
import threading
import uuid

from assemblyline.al.common import forge, queue, remote_datatypes
from assemblyline.al.common.error_template import ERROR_MAP

TYPE_BACKUP = 0
TYPE_RESTORE = 1

DATABASE_NUM = 3
RETRY_PRINT_THRESHOLD = 1000
COUNT_INCREMENT = 1000
LOW_THRESHOLD = 10000
HIGH_THRESHOLD = 50000


class SystemBackup(object):
    def __init__(self, backup_file_path):
        self.backup_file_path = backup_file_path
        self.ds = forge.get_datastore()

        # Static maps
        self.BUCKET_MAP = {
            "blob": self.ds.blobs,
            "node": self.ds.nodes,
            "profile": self.ds.profiles,
            "signature": self.ds.signatures,
            "user": self.ds.users,
        }
        self.VALID_BUCKETS = sorted(self.BUCKET_MAP.keys())

    def list_valid_buckets(self):
        return self.VALID_BUCKETS

    # noinspection PyProtectedMember
    def backup(self, bucket_list=None):
        if bucket_list is None:
            bucket_list = self.VALID_BUCKETS

        for bucket in bucket_list:
            if bucket not in self.VALID_BUCKETS:
                print "ERROR: '%s' is not a valid bucket.\n\nChoose one of the following:\n\t%s\n" \
                      % (bucket, "\n\t".join(self.VALID_BUCKETS))
                return

        with open(self.backup_file_path, "wb") as out_file:
            print "Starting system backup... [%s bucket(s)]" % ", ".join(bucket_list)
            output = {}
            for bucket in bucket_list:
                data = {k: self.ds._get_bucket_item(self.BUCKET_MAP[bucket], k)
                        for k in self.ds._stream_bucket_debug_keys(self.BUCKET_MAP[bucket])}
                output[bucket] = data
                print "\t[x] %s" % bucket.upper()

            print "Saving backup to file %s..." % self.backup_file_path
            out_file.write(json.dumps(output))

        print "Backup completed!\n"

    # noinspection PyProtectedMember
    def restore(self, bucket_list=None):
        print "Loading backup file %s ..." % self.backup_file_path

        with open(self.backup_file_path, "rb") as bck_file:
            restore = json.loads(bck_file.read())

        if bucket_list is None:
            bucket_list = self.VALID_BUCKETS

        for bucket in bucket_list:
            if bucket not in self.VALID_BUCKETS:
                print "ERROR: '%s' is not a valid bucket.\n\nChoose one of the following:\n\t%s\n" \
                      % (bucket, "\n\t".join(self.VALID_BUCKETS))
                return

        print "Restoring data in buckets... [%s]" % ", ".join(bucket_list)
        errors = []
        for bucket in bucket_list:
            if bucket not in restore:
                print "\t[ ] %s" % bucket.upper()
                errors.append(bucket)
            else:
                for k, v in restore[bucket].iteritems():
                    v = self.ds.sanitize(bucket, v, k)
                    self.ds._save_bucket_item(self.BUCKET_MAP[bucket], k, v)

                print "\t[x] %s" % bucket.upper()

        if len(errors) > 0:
            print "Backup restore complete with missing data.\nThe following buckets don't have any data " \
                  "to restore:\n\t%s \n" % "\n\t".join(errors)
        else:
            print "Backup restore complete!\n"


class DistributedBackup(object):
    def __init__(self, working_dir, worker_count=50, spawn_workers=True):
        self.working_dir = working_dir
        self.ds = forge.get_datastore()
        self.plist = []
        self.instance_id = str(uuid.uuid4())
        self.follow_queue = queue.NamedQueue("r-follow_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
        self.hash_queue = remote_datatypes.Hash("r-hash_%s" % self.instance_id, db=DATABASE_NUM)
        self.backup_queue = queue.NamedQueue('r-backup_%s' % self.instance_id, db=DATABASE_NUM, ttl=1800)
        self.backup_done_queue = queue.NamedQueue("r-backup-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
        self.restore_done_queue = queue.NamedQueue("r-restore-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
        self.bucket_error = []

        self.BUCKET_MAP = {
            "alert": self.ds.alerts,
            "blob": self.ds.blobs,
            "emptyresult": self.ds.emptyresults,
            "error": self.ds.errors,
            "file": self.ds.files,
            "filescore": self.ds.filescores,
            "node": self.ds.nodes,
            "profile": self.ds.profiles,
            "result": self.ds.results,
            "signature": self.ds.signatures,
            "submission": self.ds.submissions,
            "user": self.ds.users,
        }
        self.VALID_BUCKETS = sorted(self.BUCKET_MAP.keys())
        self.worker_count = worker_count
        self.spawn_workers = spawn_workers
        self.current_type = None

    def terminate(self):
        self._cleanup_queues(self.current_type)

    def _cleanup_queues(self, task_type):
        if task_type == TYPE_BACKUP:
            print "\nCleaning up backup queues for ID: %s..." % self.instance_id
            self.backup_queue.delete()
            for _ in xrange(100):
                self.backup_queue.push({"is_done": True})
            time.sleep(2)
            self.backup_queue.delete()
            self.backup_done_queue.delete()
        else:
            print "\nCleaning up restore queues for ID: %s..." % self.instance_id
            self.restore_done_queue.delete()

        self.follow_queue.delete()
        self.hash_queue.delete()

    def _done_thread(self, done_type):
        # Init
        map_count = {}
        missing_map_count = {}
        t_count = 0
        e_count = 0
        t0 = time.time()
        t_last = t0
        done_count = 0

        # Initialise by type
        if done_type == TYPE_BACKUP:
            title = "Backup"
            done_queue = self.backup_done_queue
        else:
            title = "Restore"
            done_queue = self.restore_done_queue

        while True:
            msg = queue.select(done_queue, timeout=1)
            if not msg:
                continue

            _, data = msg
            if data.get("is_done", False):
                done_count += 1
            else:
                if data.get('success', False):
                    t_count += 1

                    bucket_name = data['bucket_name']

                    if data.get("missing", False):
                        if bucket_name not in missing_map_count:
                            missing_map_count[bucket_name] = 0

                        missing_map_count[bucket_name] += 1
                    else:
                        if bucket_name not in map_count:
                            map_count[bucket_name] = 0

                        map_count[bucket_name] += 1

                    if t_count % COUNT_INCREMENT == 0:
                        new_t = time.time()
                        print "%s (%s at %s keys/sec) ==> %s" % (t_count,
                                                                 new_t - t_last,
                                                                 int(COUNT_INCREMENT / (new_t - t_last)),
                                                                 map_count)
                        t_last = new_t
                else:
                    e_count += 1

            if done_count == self.worker_count:
                break

        # Cleanup
        self.hash_queue.delete()

        summary = ""
        summary += "%s DONE! (%s keys backed up - %s errors - %s secs)\n" % \
                   (title, t_count, e_count, time.time() - t0)
        summary += "\n############################################\n"
        summary += "########## %08s SUMMARY ################\n" % title.upper()
        summary += "############################################\n\n"

        for k, v in map_count.iteritems():
            summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(missing_map_count.keys()) > 0:
            summary += "\n\nMissing data:\n\n"
            for k, v in missing_map_count.iteritems():
                summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.bucket_error) > 0:
            summary += "\nThese buckets failed to %s completely: %s\n" % (title.lower(), self.bucket_error)
        print summary

    # noinspection PyProtectedMember
    def _key_streamer(self, bucket_name, _):
        for x in self.ds._stream_bucket_debug_keys(self.BUCKET_MAP[bucket_name]):
            yield x

    def _search_streamer(self, bucket_name, query):
        for x in self.ds.stream_search(bucket_name, query, fl="_yz_rk", item_buffer_size=500):
            yield x['_yz_rk']

    # noinspection PyBroadException,PyProtectedMember
    def backup(self, bucket_list, follow_keys=False, query=None):
        if query:
            stream_func = self._search_streamer
        else:
            stream_func = self._key_streamer

        for bucket in bucket_list:
            if bucket not in self.VALID_BUCKETS:
                print "\n%s is not a valid bucket.\n\nThe list of valid buckets is the following:\n\n\t%s\n" % \
                      (bucket.upper(), "\n\t".join(self.VALID_BUCKETS))
                return
        try:
            # Cleaning queues
            self.current_type = TYPE_BACKUP

            # Spawning workers
            if self.spawn_workers:
                print "Spawning %s backup workers ..." % self.worker_count
                devnull = open(os.devnull, 'w')
                for x in xrange(self.worker_count):
                    run_dir = __file__[:__file__.index("common/")]
                    p = subprocess.Popen([os.path.join(run_dir, "run", "invoke.sh"),
                                          os.path.join(run_dir, "run", "distributed_worker.py"),
                                          str(TYPE_BACKUP),
                                          str(x),
                                          self.working_dir,
                                          self.instance_id],
                                         stderr=devnull,
                                         stdout=devnull)
                    self.plist.append(p)
                print "All backup workers started!"
            else:
                print "No spawning any workers. You need to manually spawn %s workers..." % self.worker_count

            # Start done thread
            t = threading.Thread(target=self._done_thread, args=(TYPE_BACKUP,), name="Done thread")
            t.setDaemon(True)
            t.start()

            # Process data buckets
            print "Send all keys of buckets [%s] to be backed-up..." % ', '.join(bucket_list)
            if follow_keys:
                print "Distributed backup will perform a deep backup."
            for bucket_name in bucket_list:
                try:
                    count = 0
                    for key in stream_func(bucket_name, query):
                        self.backup_queue.push({"bucket_name": bucket_name, "key": key, "follow_keys": follow_keys})

                        count += 1
                        if count % COUNT_INCREMENT == 0:
                            if self.backup_queue.length() > HIGH_THRESHOLD:
                                retry = 0
                                while self.backup_queue.length() > LOW_THRESHOLD:
                                    if retry % RETRY_PRINT_THRESHOLD == 0:
                                        print "WARNING: Backup queue reached max threshold (%s). " \
                                              "Waiting for queue size " \
                                              "to reach %s before sending more keys... [%s]" \
                                              % (HIGH_THRESHOLD, LOW_THRESHOLD, self.backup_queue.length())
                                    time.sleep(0.1)
                                    retry += 1
                except Exception, e:
                    self.follow_queue.delete()
                    self.backup_queue.delete()
                    self.hash_queue.delete()
                    print e
                    print "Error occurred while processing bucket %s." % bucket_name
                    self.bucket_error.append(bucket_name)

            # Push kill message to all workers
            print "All keys sent for all buckets. Sending kill command and waiting for workers to finish..."
            for _ in xrange(self.worker_count):
                self.backup_queue.push({"is_done": True})

            # Wait for workers to finish
            t.join()
        except Exception, e:
            print e
        finally:
            print "Backup of %s terminated.\n" % ", ".join(bucket_list)

    def restore(self):
        try:
            self.current_type = TYPE_RESTORE

            # Spawning workers
            print "Spawning %s restore workers ..." % self.worker_count
            devnull = open(os.devnull, 'w')
            for x in xrange(self.worker_count):
                run_dir = __file__[:__file__.index("common/")]
                p = subprocess.Popen([os.path.join(run_dir, "run", "invoke.sh"),
                                      os.path.join(run_dir, "run", "distributed_worker.py"),
                                      str(TYPE_RESTORE),
                                      str(x),
                                      self.working_dir,
                                      self.instance_id],
                                     stderr=devnull,
                                     stdout=devnull)
                self.plist.append(p)
            print "All restore workers started, waiting for them to import all the data..."

            # Start done thread
            t = threading.Thread(target=self._done_thread, args=(TYPE_RESTORE,), name="Done thread")
            t.setDaemon(True)
            t.start()

            # Wait for workers to finish
            t.join()
        except Exception, e:
            print e
        finally:
            print "Restore of backup in %s terminated.\n" % self.working_dir


def _string_getter(data):
    if data is not None:
        return [data]
    else:
        return []


def _result_getter(data):
    if data is not None:
        return [x for x in data if not x.endswith('.e')]
    else:
        return []


def _emptyresult_getter(data):
    if data is not None:
        return [x for x in data if x.endswith('.e')]
    else:
        return []


def _error_getter(data):
    if data is not None:
        return [x for x in data if x.rsplit('.e', 1)[1] not in ERROR_MAP.keys()]
    else:
        return []


def _srl_getter(data):
    if data is not None:
        return [x[:64] for x in data]
    else:
        return []


def _file_getter(data):
    if data is not None:
        return [x[1] for x in data]
    else:
        return []


def _result_file_getter(data):
    if data is not None:
        supp = data.get("supplementary", []) + data.get("extracted", [])
        return _file_getter(supp)
    else:
        return []

FOLLOW_KEYS = {
    "alert": [
        ('submission', 'sid', _string_getter),
    ],
    "submission": [
        ('result', 'results', _result_getter),
        ('emptyresult', 'results', _emptyresult_getter),
        ('error', 'errors', _error_getter),
        ('file', 'results', _srl_getter),
        ('file', 'files', _file_getter),
        ('file', 'errors', _srl_getter),
    ],
    "results": [
        ('file', 'response', _result_file_getter),
    ]
}


# noinspection PyProtectedMember,PyBroadException
class BackupWorker(object):
    def __init__(self, wid, worker_type, working_dir, instance_id):
        self.working_dir = working_dir
        self.worker_id = wid
        self.ds = forge.get_datastore()
        self.worker_type = worker_type
        self.instance_id = instance_id

        if worker_type == TYPE_BACKUP:
            self.hash_queue = remote_datatypes.Hash("r-hash_%s" % self.instance_id, db=DATABASE_NUM)
            self.follow_queue = queue.NamedQueue("r-follow_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
            self.queue = queue.NamedQueue("r-backup_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
            self.done_queue = queue.NamedQueue("r-backup-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
        else:
            self.hash_queue = None
            self.follow_queue = None
            self.queue = None
            self.done_queue = queue.NamedQueue("r-restore-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)

    def _backup(self):
        done = False
        current_queue = self.queue
        with open(os.path.join(self.working_dir, "backup.part%s" % self.worker_id), "wb") as backup_file:
            while True:
                data = current_queue.pop(timeout=1)
                if not data and done:
                    break
                elif not data:
                    continue

                if isinstance(data, list):
                    data = data[0]

                if data.get('is_done', False) and not done:
                    current_queue = self.follow_queue
                    done = True
                    continue
                elif data.get('is_done', False) and done:
                    # Go someone else done message. Push it back on the queue and sleep...
                    self.queue.push({"is_done": True})
                    time.sleep(1)
                    continue

                missing = False
                success = True
                try:
                    to_write = self.ds._get_bucket_item(self.ds.get_bucket(data['bucket_name']), data['key'])
                    if to_write:
                        if data.get('follow_keys', False):
                            for bucket, bucket_key, getter in FOLLOW_KEYS.get(data['bucket_name'], []):
                                for key in getter(to_write.get(bucket_key, None)):
                                    hash_key = "%s_%s" % (bucket, key)
                                    if not self.hash_queue.exists(hash_key):
                                        self.hash_queue.add(hash_key, "True")
                                        self.follow_queue.push({"bucket_name": bucket, "key": key, "follow_keys": True})

                        backup_file.write(json.dumps((data['bucket_name'], data['key'], to_write)) + "\n")
                    else:
                        missing = True

                except:
                    success = False

                self.done_queue.push({"is_done": False,
                                      "success": success,
                                      "missing": missing,
                                      "bucket_name": data['bucket_name'],
                                      "key": data['key']})

    # noinspection PyUnresolvedReferences
    def _restore(self):
        with open(os.path.join(self.working_dir, "backup.part%s" % self.worker_id), "rb") as input_file:
            for l in input_file.xreadlines():
                bucket_name, key, data = json.loads(l)

                success = True
                try:
                    v = self.ds.sanitize(bucket_name, data, key)
                    self.ds._save_bucket_item(self.ds.get_bucket(bucket_name), key, v)
                except:
                    success = False

                self.done_queue.push({"is_done": False,
                                      "success": success,
                                      "missing": False,
                                      "bucket_name": bucket_name,
                                      "key": key})

    def run(self):
        if self.worker_type == TYPE_BACKUP:
            self._backup()
        else:
            self._restore()

        self.done_queue.push({"is_done": True})

if __name__ == "__main__":
    import sys

    # noinspection PyBroadException
    try:
        backup = sys.argv[1]
        backup_manager = DistributedBackup(backup, worker_count=1, spawn_workers=False)
        backup_manager.restore()
    except:
        print "No backup to restore"
