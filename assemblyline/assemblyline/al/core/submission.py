""" File Submission Service and Interfaces.

The Submission service encapsulates the core functionality of accepting,
triaging and forwarding a submission to the dispatcher.

SubmissionServer is typically exposed via HTTP interface implemented by al_ui,
however the core logic is implemented in SubmissionService to provide 
seperation between the network rpc interface and the actual submission logic.

There are three primary modes of submission:

  two-phase (presubmit + submit)
  inline  (submit file)
  existing (submit a file that is already in the file cache/SAN)

In two-phase mode, submission is a presubmit followed by a submit. 
A 'presubmit' is sent to the submission service first. If the server already 
has a copy of the sample it indicates as such to the client which saves the 
client from copying the file again. Once the client has copied the file 
(if required) it then issues a final 'submit'.

"""
import logging
import os
import pprint
import uuid
import tempfile
import time

from assemblyline.al.common import forge
from assemblyline.al.common.task import Task
from assemblyline.al.common.remote_datatypes import ExpiringHash
from assemblyline.al.core.filestore import CorruptedFileStoreException
from assemblyline.common import digests
from assemblyline.common import identify
from assemblyline.common.charset import safe_str
from assemblyline.common.isotime import now_as_iso

log = logging.getLogger('assemblyline.submission')

config = forge.get_config()

SUBMISSION_AUTH = (safe_str(config.submissions.user), safe_str(config.submissions.password))
SHARDS = config.core.dispatcher.shards


class SubmissionException(Exception):
    pass


def assert_valid_file(path):
    if not os.path.exists(path):
        raise Exception('File does not exist: %s' % path)
    if os.path.isdir(path):
        raise Exception('Expected file. Found directory: %s' % path)


def assert_valid_sha256(sha256):
    if len(sha256) != 64:
        raise Exception('Invalid SHA256: %s' % sha256)


def effective_ttl(settings):
    return settings.get('ttl', config.submissions.ttl)


def max_extracted(settings):
    return settings.get('max_extracted', config.services.limits.max_extracted)


def max_supplementary(settings):
    return settings.get('max_supplementary', config.services.limits.max_supplementary)


def ttl_to_expiry(ttl):
    return now_as_iso(int(ttl) * 24 * 60 * 60)


class SubmissionWrapper(object):

    @classmethod
    def check_exists(cls, transport, sha256_list):
        log.debug("CHECK EXISTS (): %s", sha256_list)
        existing = []
        missing = []
        for sha256 in sha256_list:
            if not transport.exists(sha256):
                missing.append(sha256)
            else:
                existing.append(sha256)
        return {'existing': existing, 'missing': missing}

    # noinspection PyBroadException
    @classmethod
    def identify(cls, transport, storage, sha256, **kw):
        """ Identify a file. """
        assert_valid_sha256(sha256)

        classification = kw['classification']

        kw['ttl'] = ttl = effective_ttl(kw)
        kw['__expiry_ts__'] = expiry = ttl_to_expiry(ttl)

        # By the time identify is called, either the file was in our cache
        # and we freshed its ttl or the client has successfully transfered
        # the file to us.
        local_path = transport.local_path(sha256)
        if not local_path:
            path = kw.get("path", None)
            if path and os.path.exists(path):
                local_path = path

        if not transport.exists(sha256):
            log.warning('File specified is not on server: %s %s.',
                        sha256, str(transport))
            return None

        temporary_path = fileinfo = None
        try:
            if not local_path:
                temporary_path = tempfile.mktemp(prefix="submission.identify")
                transport.download(sha256, temporary_path)
                local_path = temporary_path

            fileinfo = identify.fileinfo(local_path)

            storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except:  # pylint: disable=W0702
                    pass

        return fileinfo

    @classmethod
    def presubmit(cls, transport, sha256, **kw):
        """ Execute a presubmit.

            Checks if this file is already cached.
            If not, it returns a location for the client to copy the file.


            result dictionary example:
            { 'exists': False,
              'sha256': u'012345678....9876543210',
              'upload_path': u'/home/aluser/012345678....9876543210'
            }

            """
        log.debug("PRESUBMIT: %s", sha256)
        assert_valid_sha256(sha256)

        if transport.exists(sha256):
            return SubmissionWrapper.result_dict(transport, sha256, True, None, kw)

        # We don't have this file. Tell the client as much and tell it where
        # to transfer the file before issuing the final submit.
        log.debug('Cache miss. Client should transfer to %s', sha256)
        return SubmissionWrapper.result_dict(transport, sha256, False, sha256, kw)

    # noinspection PyBroadException
    @classmethod
    def submit(cls, transport, storage, sha256, path, priority, submitter, **kw):
        """ Execute a submit.

        Any kw are passed along in the dispatched request.

        """
        assert_valid_sha256(sha256)
        queue = forge.get_dispatch_queue()

        classification = kw['classification']

        kw['max_extracted'] = max_extracted(kw)
        kw['max_supplementary'] = max_supplementary(kw)
        kw['ttl'] = ttl = effective_ttl(kw)
        kw['__expiry_ts__'] = expiry = ttl_to_expiry(ttl)

        # By the time submit is called, either the file was in our cache
        # and we freshed its ttl or the client has successfully transfered
        # the file to us.
        local_path = transport.local_path(sha256)

        if not transport.exists(sha256):
            raise SubmissionException('File specified is not on server: %s %s.' % (sha256, str(transport)))

        root_sha256 = sha256
        temporary_path = massaged_path = None
        try:
            if not local_path:
                temporary_path = tempfile.mktemp(prefix="submission.submit")
                transport.download(sha256, temporary_path)
                local_path = temporary_path

            fileinfo = identify.fileinfo(local_path)
            if fileinfo['sha256'] != sha256:
                raise CorruptedFileStoreException('SHA256 mismatch between received '
                                                  'and calculated sha256. %s != %s' % (sha256, fileinfo['sha256']))
            storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)

            decode_file = forge.get_decode_file()
            massaged_path, _, fileinfo, al_meta = decode_file(local_path, fileinfo)

            if massaged_path:
                local_path = massaged_path
                sha256 = fileinfo['sha256']

                transport.put(local_path, sha256)
                storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)

            ignore_size = kw.get('ignore_size', False)
            max_size = config.submissions.max.size
            if fileinfo['size'] > max_size and not ignore_size:
                msg = "File too large (%d > %d). Submission failed" % (fileinfo['size'], max_size)
                raise SubmissionException(msg)

            # We'll just merge the mandatory arguments, fileinfo, and any
            # optional kw and pass those all on to the dispatch callback.
            task_args = fileinfo
            task_args.update(kw)
            task_args.update({
                'original_selected': kw.get('selected', []),
                'root_sha256': root_sha256,
                'srl': sha256,
                'sha256': sha256,
                'priority': priority,
                'submitter': submitter,
                'path': safe_str(path)})

            if 'metadata' in task_args:
                task_args['metadata'].update(al_meta)
            else:
                task_args['metadata'] = al_meta

            submit_task = Task.create(**task_args)
            if submit_task.is_initial():
                storage.create_submission(
                    submit_task.sid,
                    submit_task.as_submission_record(),
                    [(os.path.basename(path), submit_task.srl)])
            log.debug("Submission complete. Dispatching: %s", submit_task)

            queue.send(submit_task, shards=SHARDS)

            return submit_task.raw
        finally:
            if massaged_path:
                try:
                    os.unlink(massaged_path)
                except:  # pylint:disable=W0702
                    pass

            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except:  # pylint:disable=W0702
                    pass

    @classmethod
    def submit_inline(cls, storage, transport, file_paths, **kw):
        """ Submit local samples to the submission service.

            submit_inline can be used when the sample to submit is already
            local to the submission service. It does the presumit, filestore
            upload and submit.

            Any kw are passed to the Task created to dispatch this submission.
        """
        classification = kw['classification']

        kw['max_extracted'] = max_extracted(kw)
        kw['max_supplementary'] = max_supplementary(kw)
        kw['ttl'] = ttl = effective_ttl(kw)
        kw['__expiry_ts__'] = expiry = ttl_to_expiry(ttl)

        submissions = []
        file_tuples = []
        dispatch_request = None
        # Generate static fileinfo data for each file.
        for file_path in file_paths:

            file_name = os.path.basename(file_path)
            fileinfo = identify.fileinfo(file_path)

            ignore_size = kw.get('ignore_size', False)
            max_size = config.submissions.max.size
            if fileinfo['size'] > max_size and not ignore_size:
                msg = "File too large (%d > %d). Submission Failed" % \
                      (fileinfo['size'], max_size)
                raise SubmissionException(msg)

            decode_file = forge.get_decode_file()
            temp_path, original_name, fileinfo, al_meta = \
                decode_file(file_path, fileinfo)

            if temp_path:
                file_path = temp_path
                if not original_name:
                    original_name = os.path.splitext(file_name)[0]
                file_name = original_name

            sha256 = fileinfo['sha256']

            storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)

            file_tuples.append((file_name, sha256))

            if not transport.exists(sha256):
                log.debug('File not on remote filestore. Uploading %s', sha256)
                transport.put(file_path, sha256, location='near')

            if temp_path:
                os.remove(temp_path)

            # We'll just merge the mandatory arguments, fileinfo, and any
            # optional kw and pass those all on to the dispatch callback.
            task_args = fileinfo
            task_args['priority'] = 0  # Just a default.
            task_args.update(kw)
            task_args['srl'] = sha256
            task_args['original_filename'] = file_name
            task_args['path'] = file_name

            if 'metadata' in task_args:
                task_args['metadata'].update(al_meta)
            else:
                task_args['metadata'] = al_meta

            dispatch_request = Task.create(**task_args)
            submissions.append(dispatch_request)

        storage.create_submission(
            dispatch_request.sid,
            dispatch_request.as_submission_record(),
            file_tuples)

        dispatch_queue = forge.get_dispatch_queue()
        for submission in submissions:
            dispatch_queue.submit(submission)

        log.debug("Submission complete. Dispatched: %s", dispatch_request)

        # Ugly - fighting with task to give UI something that makes sense.
        file_result_tuples = \
            zip(file_paths, [dispatch_request.raw for dispatch_request in submissions])
        result = submissions[0].raw.copy()
        fileinfos = []
        for filename, result in file_result_tuples:
            finfo = result['fileinfo']
            finfo['original_filename'] = os.path.basename(filename)
            finfo['path'] = finfo['original_filename']
            fileinfos.append(finfo)
        result['fileinfo'] = fileinfos
        return result

    # noinspection PyBroadException
    @classmethod
    def submit_multi(cls, storage, transport, files, **kw):
        """ Submit all files into one submission

            submit_multi can be used when all the files are already present in the
            file storage.

            files is an array of (name, sha256) tuples

            Any kw are passed to the Task created to dispatch this submission.
        """
        sid = str(uuid.uuid4())
        classification = kw['classification']

        kw['max_extracted'] = max_extracted(kw)
        kw['max_supplementary'] = max_supplementary(kw)
        kw['ttl'] = ttl = effective_ttl(kw)
        kw['__expiry_ts__'] = expiry = ttl_to_expiry(ttl)

        submissions = []
        temporary_path = None
        dispatch_request = None
        # Generate static fileinfo data for each file.
        for name, sha256 in files:
            local_path = transport.local_path(sha256)

            if not transport.exists(sha256):
                raise SubmissionException('File specified is not on server: %s %s.' % (sha256, str(transport)))

            try:
                if not local_path:
                    temporary_path = tempfile.mktemp(prefix="submission.submit_multi")
                    transport.download(sha256, temporary_path)
                    local_path = temporary_path

                fileinfo = identify.fileinfo(local_path)
                storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)

                decode_file = forge.get_decode_file()
                massaged_path, new_name, fileinfo, al_meta = \
                    decode_file(local_path, fileinfo)

                if massaged_path:
                    name = new_name
                    local_path = massaged_path
                    sha256 = fileinfo['sha256']

                    if not transport.exists(sha256):
                        transport.put(local_path, sha256)
                    storage.save_or_freshen_file(sha256, fileinfo, expiry, classification)

                ignore_size = kw.get('ignore_size', False)
                max_size = config.submissions.max.size
                if fileinfo['size'] > max_size and not ignore_size:
                    msg = "File too large (%d > %d). Submission failed" % (fileinfo['size'], max_size)
                    raise SubmissionException(msg)

                # We'll just merge the mandatory arguments, fileinfo, and any
                # optional kw and pass those all on to the dispatch callback.
                task_args = fileinfo
                task_args['priority'] = 0  # Just a default.
                task_args.update(kw)
                task_args['srl'] = sha256
                task_args['original_filename'] = name
                task_args['sid'] = sid
                task_args['path'] = name

                if 'metadata' in task_args:
                    task_args['metadata'].update(al_meta)
                else:
                    task_args['metadata'] = al_meta

                dispatch_request = Task.create(**task_args)
                submissions.append(dispatch_request)
            finally:
                if temporary_path:
                    try:
                        os.unlink(temporary_path)
                    except:  # pylint: disable=W0702
                        pass

        storage.create_submission(
            dispatch_request.sid,
            dispatch_request.as_submission_record(),
            files)

        dispatch_queue = forge.get_dispatch_queue()
        for submission in submissions:
            dispatch_queue.submit(submission)

        log.debug("Submission complete. Dispatched: %s", dispatch_request)
        return submissions[0].raw.copy()

    @classmethod
    def watch(cls, sid, watch_queue):
        t = Task.watch(**{
            'priority': config.submissions.max.priority,
            'sid': sid,
            'watch_queue': watch_queue,
        })
        n = forge.determine_dispatcher(sid)
        forge.get_control_queue('control-queue-' + str(n)).push(t.raw)

    @classmethod
    def result_dict(cls, transport, sha256, exists, upload_path, kw):
        return {
            'exists': exists,
            'upload_path': upload_path,
            'filestore': str(transport),
            'sha256': sha256,
            'kwargs': kw,
        }


class SubmissionService(object):
    def __init__(self):
        self.storage = forge.get_datastore()
        self.transport = forge.get_filestore()

        log.info("Submission service instantiated. Transport::{0}".format(
            self.transport))

    def check_exists(self, sha256_list):
        return SubmissionWrapper.check_exists(self.transport, sha256_list)

    def identify(self, sha256, **kw):
        return SubmissionWrapper.identify(self.transport, self.storage, sha256, **kw)

    def presubmit(self, sha256, **kw):
        return SubmissionWrapper.presubmit(self.transport, sha256, **kw)

    def submit(self, sha256, path, priority, submitter, **kw):
        return SubmissionWrapper.submit(self.transport, self.storage, sha256, path, priority, submitter, **kw)

    def submit_inline(self, file_paths, **kw):
        return SubmissionWrapper.submit_inline(self.storage, self.transport, file_paths, **kw)

    def submit_multi(self, files, **kw):
        return SubmissionWrapper.submit_multi(self.storage, self.transport, files, **kw)

    @classmethod
    def watch(cls, sid, watch_queue):
        return SubmissionWrapper.watch(sid, watch_queue)

    def result_dict(self, sha256, exists, upload_path, kw):
        # noinspection PyProtectedMember
        return SubmissionWrapper.result_dict(self.transport, sha256, exists, upload_path, kw)


class SubmissionClient(object):
    def __init__(self, server_url=None, datastore=None):
        if not server_url:
            server_url = config.submissions.url

        self.server_url = server_url
        self.transport = forge.get_filestore()
        self.datastore = datastore
        self.is_unix = os.name == "posix"
        if not self.is_unix:
            from assemblyline_client import Client
            self.client = Client(self.server_url, auth=SUBMISSION_AUTH)
        elif self.datastore is None:
            self.datastore = forge.get_datastore()

    def check_srls(self, srl_list):
        if self.is_unix:
            return self._check_srls_unix(srl_list)
        else:
            return self._check_srls_windows(srl_list)

    def _check_srls_unix(self, srl_list):
        if not srl_list:
            return True
        result = SubmissionWrapper.check_exists(self.transport, srl_list)
        return len(result.get('existing', [])) == len(srl_list)

    def _check_srls_windows(self, srl_list):
        if not srl_list:
            return True
        result = self.client.submit.checkexists(*srl_list)
        return len(result.get('existing', [])) == len(srl_list)

    def identify_supplementary(self, rd, **kw):
        # Pass along all parameters as query arguments.
        submits = {k: dict(kw.items() + v.items()) for k, v in rd.iteritems()}
        if self.is_unix:
            return self._identify_supplementary_unix(submits)
        else:
            return self._identify_supplementary_windows(submits)

    def _identify_supplementary_unix(self, submits):
        submit_results = {}
        for key, submit in submits.iteritems():
            file_info = SubmissionWrapper.identify(self.transport, self.datastore, **submit)
            if file_info:
                submit_result = {"status": "succeeded", "fileinfo": file_info}
            else:
                submit_result = {"status": "failed", "fileinfo": {}}
            submit_results[key] = submit_result
        return submit_results

    def _identify_supplementary_windows(self, submits):
        return self.client.submit.identify(submits)

    def presubmit_local_files(self, file_paths, **kw):
        default_error = {'succeeded': False, 'error': 'Unknown Error'}
        presubmit_requests = {}
        presubmit_results = {}

        ignore_size = kw.get('ignore_size', False)
        max_size = config.submissions.max.size

        # Prepare the batch presubmit.
        rid_map = {}
        for rid, local_path in enumerate(file_paths):
            rid = str(rid)
            rid_map[rid] = local_path
            try:
                assert_valid_file(local_path)
                d = digests.get_digests_for_file(local_path,
                                                 calculate_entropy=False)
                if d['size'] > max_size and not ignore_size:
                    presubmit_results[rid] = {
                        'succeeded': False,
                        'error': 'file too large (%d > %d). Skipping' % (d['size'], max_size),
                    }
                    continue
                presubmit_requests[rid] = d
                # Set a default error. Overwritten on success.
                presubmit_results[rid] = default_error.copy()
            except Exception as ex:  # pylint: disable=W0703
                log.error("Exception processing local file: %s. Skipping", ex)
                presubmit_results[rid] = {
                    'succeeded': False,
                    'error': 'local failure before presubmit: {0}'.format(ex),
                }
                continue

        if self.is_unix:
            presubmit_results = self._presubmit_local_files_unix(presubmit_requests, presubmit_results)
        else:
            presubmit_results = self._presubmit_local_files_windows(presubmit_requests, presubmit_results)

        if len(presubmit_results) != len(file_paths):
            log.error('Problem submitting %s: %s',
                      pprint.pformat(file_paths),
                      pprint.pformat(presubmit_results))

        # noinspection PyUnresolvedReferences
        for rid, result in presubmit_results.iteritems():
            result['path'] = rid_map[rid]

        return presubmit_results

    def _presubmit_local_files_unix(self, presubmit_requests, presubmit_results):
        for key, presubmit in presubmit_requests.iteritems():
            succeeded = True
            presubmit_result = {}
            try:
                presubmit_result = SubmissionWrapper.presubmit(self.transport, **presubmit)
            except Exception as e:  # pylint: disable=W0703
                succeeded = False
                msg = 'Failed to presubmit for {0}:{1}'.format(key, e)
                presubmit_result['error'] = msg
            presubmit_result['succeeded'] = succeeded
            presubmit_results[key] = presubmit_result
        return presubmit_results

    def _presubmit_local_files_windows(self, presubmit_requests, presubmit_results):
        presubmit_results.update(self.client.submit.presubmit(presubmit_requests))

        return presubmit_results

    def submit_existing_file(self, path, **kw):
        request = {
            0: {
                'path': safe_str(path),
                'sha256': kw['sha256'],
            }
        }

        return self.submit_requests(request, **kw)

    def submit_local_files(self, file_requests, **kw):
        results = {}

        file_paths = [
            file_requests[k]['path'] for k in sorted(file_requests.keys(), key=int)
        ]

        successful, errors = \
            self.transfer_local_files(file_paths, location='near', **kw)

        for k in successful.keys():
            req = file_requests.get(k, {})
            display_name = req.pop('display_name')
            req['path'] = display_name
            ret = successful[k]
            ret.update(req)

            # This prevents a badly written service to resubmit the file originally submitted
            if successful[k].get('sha256', None) == kw.get('psrl', None):
                path = successful[k]['path']
                errors[k] = {
                    'succeeded': False,
                    'path': path,
                    'error': "File submission was aborted for file '%s' because it the same as its parent." % path
                }
                log.warning("Service is trying to submit the parent file as an extracted file.")
                del successful[k]
            elif req.get('submission_tag') is not None:
                # Save off any submission tags
                st_name = "st/%s/%s" % (kw.get('psrl', None), successful[k].get('sha256', None))
                eh = ExpiringHash(st_name, ttl=7200)
                for st_name, st_val in req['submission_tag'].iteritems():
                    eh.add(st_name, st_val)

        # Send the submit requests.
        if successful:
            results = self.submit_requests(successful, **kw)
        else: 
            log.warn('Nothing to submit after presubmission processing.')

        results.update(errors)

        return results 

    def submit_requests(self, rd, **kw):
        # Pass along all parameters as query arguments.
        submits = {k: dict(kw.items() + v.items()) for k, v in rd.iteritems()}
        if self.is_unix:
            return self._submit_requests_unix(submits)
        else:
            return self._submit_requests_windows(submits)

    def _submit_requests_unix(self, submits):
        submit_results = {}
        for key, submit in submits.iteritems():
            path = submit.get('path', './path/missing')
            if 'description' not in submit:
                submit['description'] = "Inspection of file: %s" % path
            submit_result = SubmissionWrapper.submit(self.transport, self.datastore, **submit)
            submit_results[key] = submit_result
        return submit_results

    def _submit_requests_windows(self, submits):
        return self.client.submit.start(submits)

    def submit_supplementary_files(self, file_requests, location='far', **kw):
        results = {}

        file_paths = [
            file_requests[k]['path'] for k in sorted(file_requests.keys(), key=int)
        ]

        successful, errors = \
            self.transfer_local_files(file_paths, location=location, **kw)

        for k in successful.keys():
            req = file_requests.get(k, {})
            ret = successful[k]
            ret.update(req)

            # This prevents a badly written service to resubmit the file originally submitted
            if successful[k].get('sha256', None) == kw.get('psrl', None):
                path = successful[k]['path']
                errors[k] = {
                    'succeeded': False,
                    'path': path,
                    'error': "File submission was aborted for file '%s' because it the same as its parent." % path
                }
                log.warning("Service is trying to submit the parent file as a supplementary file.")
                del successful[k]

        # Send the submit requests.
        if successful:
            results = self.identify_supplementary(successful, **kw)
        else: 
            log.warn('Nothing to submit after presubmission processing.')

        results.update(errors)

        return results 

    def transfer_local_files(self, file_paths, location='all', **kw):
        errors = {}
        successful = {}

        transfer_requests = self.presubmit_local_files(file_paths, **kw)

        delete = []
        # noinspection PyUnresolvedReferences
        for rid, result in transfer_requests.iteritems():
            key = result['path']
            if key not in file_paths:
                log.error("Unexpected presubmit result for %s.", key)
                delete.append(key)
                continue

            if not result['succeeded']:
                log.warn('skipping failed presubmit for %s - %s', key, result)
                errors[rid] = { 
                    'succeeded': False,
                    'path': safe_str(key),
                    'error': 'Presubmit failed: {0}'.format(result.get('error', 'Unknown Error')),
                }
                continue

        for rid in delete:
            # noinspection PyUnresolvedReferences
            del transfer_requests[rid]

        # Process presubmit results. Start building the submit requests. Keep
        # note of all files we need to transfer to server.
        files_to_transfer = []
        # noinspection PyUnresolvedReferences
        for rid, result in transfer_requests.iteritems():
            key = result['path']
            # If the file doesn't exist in filestore, let the client know they 
            # need to submit
            if not result.get('succeeded', True):
                continue
            elif not result.get('exists'):
                upload_path = result.get('upload_path')
                log.debug('File not on server. Should copy %s -> %s using %s', 
                          key, upload_path, str(self.transport))
                files_to_transfer.append((key, upload_path))
            else:
                log.debug('File is already on server.')

            # First apply the defaults
            successful[rid] = {'path': safe_str(key), 'sha256': result['sha256']}

        # Transfer any files which the server has indicated it doesn't have.
        if files_to_transfer:
            start = time.time()
            log.debug("Transfering files %s", str(files_to_transfer))
            failed_transfers = \
                self.transport.put_batch(files_to_transfer, location=location)
            if failed_transfers:
                log.error("The following files failed to transfer: %s",
                          failed_transfers)
            end = time.time()
            log.debug("Transfered %s in %s.", len(files_to_transfer),
                      (end - start))
        else:
            log.debug("NO FILES TO TRANSFER.")

        return successful, errors
