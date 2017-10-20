#!/usr/bin/env python

#pylint: disable=W0201

import uuid

dispatch_header = ('__expiry_ts__', 'submission', 'request')
dispatcher_ack = dispatch_header + ('response',) # Response for name + version.
dispatcher_response = dispatcher_ack + ('services',)
extra_fields = ('classification', 'errors', 'results')
file_record = ('fileinfo',)
service_request = dispatch_header + extra_fields + file_record
service_result = ('__expiry_ts__', 'response', 'result')
submission_record = ('__expiry_ts__', 'state', 'submission', 'services', 'times') + extra_fields

DEFAULT_SUBMISSION_TTL = 15

# This will change soon. The submission server will be responsible for saving
# the initial submission record.

service_overrides = [
    'deep_scan',
    'eligible_parents',
    'ignore_filtering',
    'ignore_size',
    'ignore_tag',
    'max_extracted',
    'max_supplementary',
]

submission_overrides = service_overrides + [
    'classification',
    'ignore_cache',
    'params',
]

parent = {
    # Tasks are structured as shown below:
    '__expiry_ts__': False,           # - Set to expiry date for submission.
    'classification': False,          # - Classification for this submission.
    'errors': False,                  # - Error keys for this submission.
    'results': False,                 # - Result keys for this submission.
    'state': False,                   # - Type ('submitted', 'serviced', ...
    'submission': False,              # - Fields in this section are basically
                                      #   constant after submission.
    'completed_queue': 'submission',  # +-- The queue name where task + final
                                      #     score should be sent when complete.
    'deep_scan': 'submission',        # +-- Instruct services to perform deep
                                      #     scan.
    'description': 'submission',      # +-- User entered description.
    'dispatch_queue': 'submission',   # +-- The queue name for the dispatcher
                                      #     who received this message.
    'eligible_parents': 'submission', # +-- Services allowed to have children.
    'generate_alert': 'submission',   # +-- Generate alert.
    'groups': 'submission',           # +-- Security groups for this request.
    'ignore_cache': 'submission',     # +-- Run selected services even if there
                                      #     are cached results.
    'ignore_filtering': 'submission', # +-- Continue to process even when
                                      #     services say to drop this request.
    'ignore_size': 'submission',      # +-- Allow files larger than MAX_SIZE.
    'ignore_tag': 'submission',       # +-- Do not skip services.
    'max_extracted': 'submission',    # +-- Max number of extracted files.
    'max_score': 'submission',        # +-- Max score for this submission.
    'max_supplementary': 'submission',# +-- Max number of supplementary files.
    'metadata': 'submission',         # +-- Additional metadata.
    'original_selected': 'submission',# +-- Selected services (pre-expansion).
    'notification_queue': 'submission',
    'notification_threshold': 'submission',
    'params': 'submission',           # +-- Parameters by service name.
    'priority': 'submission',         # +-- Priority (Lowest = 0)
    'profile': 'submission',          # +-- Profile this run.
    'psid': 'submission',             # +-- Parent submission ID.
    'received': 'submission',         # +-- Time (epoch seconds) when this
                                      #     message was received by the
                                      #     dispatcher.
    'resubmit_to': 'submission',      # +-- Add these services on resubmit.
    'root_sha256': 'submission',      # +-- The root sha256.
    'scan_key': 'submission',         # +-- Create and entry with the score.
    'sid': 'submission',              # +-- Submission ID
    'submitter': 'submission',        # +-- Submitter (User/System ID)
    'testing': 'submission',          # +-- Used for testing.
    'ttl': 'submission',              # +-- Submission's lifespan in days.
    'watch_queue': 'submission',      # +-- The queue name where updates for
                                      #     this SID should be sent.
    'request': False,                 #
    'ack_timeout': 'request',         # +-- The ack_timeout for this request.
    'config': 'request',              # +-- The services dynamic configuration.
    'depth': 'request',               # +-- Root submission = 0, children +1.
    'path': 'request',                # +-- The original path for this file.
    'psrl': 'request',                # +-- Parent SRL (or None)
    'quota_item': 'request',          # +-- Counts toward quota.
    'sent': 'request',                # +-- When the request was sent.
    'srl': 'request',                 # +-- SHA256-based Resource Locator.
    'services': False,                # - Service selection.
    'excluded': 'services',           # +-- Excluded Services
    'selected': 'services',           # +-- Selected services (This is modified
                                      #     by removing any services that are
                                      #     not applicable based on the tag).
    'skipped': 'services',            # +-- Selected services that are not
                                      #     applicable for this file.
    'times': False,                   # - Times for this task.
    'completed': 'times',             #
    'submitted': 'times',             #
    'fileinfo': False,                # - Fields in this section are set per
                                      #   file when a task is submitted. Some
                                      #   are used to dispatch. All are useful
                                      #   to services when processing a file).
    'ascii': 'fileinfo',              # +-- Dot-escaped first 64 characters.
    'hex': 'fileinfo',                # +-- Hex dump of first 64 bytes.
    'magic': 'fileinfo',              # +-- The output from libmagic which was
                                      #     used to determine the tag.
    'md5': 'fileinfo',                # +-- MD5
    'mime': 'fileinfo',               # +-- The libmagic mime type.
    'sha1': 'fileinfo',               # +-- SHA1
    'sha256': 'fileinfo',             # +-- SHA256
    'size': 'fileinfo',               # +-- File size
    'tag': 'fileinfo',                # +-- The file type or tag.
    'response': False,                # 
    'cache_key': 'response',          # +-- Used to find cached results.
    'extracted': 'response',          # +-- List of extracted local pathnames.
    'filter': 'response',             # +-- Set to 'drop' to stop this file
                                      #     from being dispatched to further
                                      #     stages.
    'message': 'response',            # +-- Typically the error message.
    'milestones': 'response',         # +-- Set by the service
    'score': 'response',              # +-- The score for this service.
    'seconds': 'response',            # +-- Used in 'ack' to set timeout.
    'service_debug_info': 'response', # +-- Set by the service
    'service_context': 'response',    # +-- Set by the service
    'service_name': 'response',       # +-- Set by the service
    'service_version': 'response',    # +-- Set by the service
    'status': 'response',             # +-- 'OK', failure, ...
    'supplementary': 'response',      # +-- List of supplementary local pathnames.
    'result': False,                  # +-- Opaque result dict returned by the
}

def copy(v):
    if isinstance(v, dict):
        return v.copy()
    elif isinstance(v, list):
        return v[:]
    else:
        return v

def dice(d, fields):
    return {k:copy(v) for k, v in d.iteritems() if k in fields}

def get_service_overrides(getter):
    d = {}
    for k in service_overrides:
        v = getter.get(k)
        if v is not None:
            d[k] = v
    return d

def get_submission_overrides(getter, field_list=submission_overrides):
    d = {}
    for k in field_list:
        v = getter.get(k)
        if v is not None:
            d[k] = v
    return d

class Child(object):
    def __init__(self, path, text, display_name=None, classification=None, submission_tag=None):
        self.classification = classification
        self.display_name = display_name
        self.path = path
        self.text = text
        self.submission_tag = submission_tag

    def as_tuple(self, srl, normalize=lambda x: x):
        display_name = self.display_name
        if not display_name:
            display_name = normalize(self.path)
        return display_name, srl, self.text, self.classification

def _classification(e, default_classification):
    if len(e) >= 4:
        return e[3]
    return default_classification

def _files(children):
    return {
        str(n): {
            'classification': c.classification,
            'path': c.path,
            'display_name': c.display_name,
            'submission_tag': c.submission_tag
        } for n, c in enumerate(children)
    }

def _requests(children, default_classification):
    return {
        e[1]: {
            'classification': _classification(e, default_classification),
            'path': e[0],
            'sha256': e[1]
        } for e in children if e[1]
    }

def _srls(children):
    return [e[1] for e in children if e[1]]

class Task(object):
    """Task objects are an abstraction layer over a raw (dict)."""
    def __init__(self, raw, **kwargs):
        self.raw = raw
        for k, v in kwargs.iteritems():
            if k in parent:
                setattr(self, k, v)

    def _container(self, name, check_only=False):
        has_parent = parent.get(name, None)

        if has_parent is None:
            return self.__dict__
        
        raw = self.raw
        if raw == None:
            return None
        
        container = raw
        if has_parent:
            container = raw.get(has_parent, None)
            if container is None:
                if check_only:
                    return None
                container = {}
                raw[has_parent] = container

        if not name in container:
            container[name] = None

        return container

    def add_extracted(self, name, text, display_name=None, classification=None, submission_tag=None):
        if name is None:
            return False
        if self.extracted is None:
            self.clear_extracted()
        limit = self.max_extracted
        if limit and len(self.extracted) >= int(limit):
            return False
        if not classification:
            classification = self.classification
        if not isinstance(submission_tag, dict):
            submission_tag = None
        self.extracted.append(Child(name, text, display_name, classification, submission_tag))
        return True

    def add_supplementary(self, name, text, display_name=None, classification=None):
        if name is None:
            return False
        if self.supplementary is None:
            self.clear_supplementary()
        limit = self.max_supplementary
        if limit and len(self.supplementary) >= int(limit):
            return False
        if not classification:
            classification = self.classification
        self.supplementary.append(Child(name, text, display_name, classification))
        return True

    def as_dispatcher_ack(self, seconds=600):
        return Task(dice(self.raw, dispatcher_ack),
                    state='acknowledged', seconds=seconds).raw

    def as_dispatcher_response(self):
        return Task(dice(self.raw, dispatcher_response),
                    state='serviced').raw

    def as_submission_record(self):
        return dice(self.raw, submission_record)

    def as_service_request(self, name):
        t = Task(dice(self.raw, service_request))
        if self.params:
            t.config = self.params.get(name, None)
        return t.raw

    def as_service_result(self):
        t = Task(dice(self.raw, service_result))
        if not t.extracted:
            t.extracted = []
        if not t.supplementary:
            t.supplementary = []
        if not t.message:
            t.message = ''
        if not t.result:
            t.result = []
        return t.raw

    def clear_extracted(self):
        self.extracted = []

    def clear_supplementary(self):
        self.supplementary = []

    def drop(self):
        self.filter = 'drop'

    def exclude_service(self, name):
        if self.excluded is None: #pylint: disable=E0203
            self.excluded = []
        self.excluded.append(name)

    def extracted_files(self):
        if not self.extracted:
            return []
        return _files(self.extracted)

    def extracted_requests(self):
        if not self.extracted:
            return {}
        return _requests(self.extracted, self.classification)

    def extracted_srls(self):
        if not self.extracted:
            return []
        return _srls(self.extracted)

    def get(self, name):
        return self.__getattr__(name)

    def get_milestone(self, name):
        if not self.milestones:
            self.milestones = {}

        return self.milestones.get(name, None)

    def get_service_params(self, service_name):
        if not service_name or not self.params:
            return {}

        return self.params.get(service_name, {})

    def get_tag_set_name(self):
        return '/'.join((self.sid, self.srl, 'tags'))

    def get_submission_tags_name(self):
        return "st/%s/%s" % (self.psrl, self.sha256)

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and self.psrl is None

    def is_response(self):
        return self.state == 'serviced'

    def is_submit(self):
        return self.state == 'submitted'

    def nonrecoverable_failure(self, message):
        self.message = message
        self.status = 'FAIL_NONRECOVERABLE'

    def recoverable_failure(self, message):
        self.message = message
        self.status = 'FAIL_RECOVERABLE'

    def report_service_context(self, context):
        if not isinstance(context, basestring):
            raise TypeError('Expected string got %s', type(context))
        self.service_context = context

    def remove(self, name):
        d = self._container(name, check_only=True)
        if d is None:
            return
        if name in d:
            del d[name]

    def select_service(self, name):
        if self.selected is None: #pylint: disable=E0203
            self.selected = []
        self.selected.append(name)

    def set_debug_info(self, debug_info):
        self.service_debug_info = debug_info

    def set_milestone(self, name, value):
        if not self.milestones:
            self.milestones = {}
        self.milestones[name] = value

    def success(self, message=None):
        self.status = 'OK'
        self.message = message
        self.score = 0
        if self.result:
            try:
                self.score = int(self.result.get('score', 0)) #pylint: disable=E1103
            except: #pylint: disable=W0702
                self.score = 0

    def supplementary_files(self):
        if not self.supplementary:
            return []
        return _files(self.supplementary)

    def supplementary_srls(self):
        if not self.supplementary:
            return []
        return _srls(self.supplementary)

    def update_from_cached(self, raw_cached):
        self.update(raw_cached)
        # Do some stricter validation... 
        return True

    def update(self, raw):
        self.response = raw['response']
        self.result = raw['result']
        return True

    def watermark(self, service_name, service_version):
        self.service_name = service_name
        self.service_version = service_version

    @classmethod
    def create(cls, **kwargs):
        defaults = {
            'description': '',
            'groups': [],
            'ignore_cache': False,
            'ignore_filtering': False,
            'ignore_tag': False,
            'priority': 0,
            'profile': False,
            'ttl': DEFAULT_SUBMISSION_TTL,
            'excluded': [],
            'params': {},
            'selected': [],
            'skipped': [],
            'completed': None,
            'submitted': None,
        }
        defaults.update(**kwargs)
        task = cls({}, **defaults)
        task.state = 'submitted'
        if task.sid is None:
            task.sid = str(uuid.uuid4())
        return task

    @classmethod
    def watch(cls, **kwargs):
        task = cls({}, **kwargs)
        task.state = 'watch'
        return task

    @classmethod
    def wrap(cls, arg):
        if isinstance(arg, cls):
            return cls(arg.raw)
        return cls(arg)

    def __getattr__(self, name):
        return self._container(name)[name]

    def __setattr__(self, name, value):
        self._container(name)[name] = value

    def __repr__(self):
        return self.__class__.__name__ + '(' + str(self.raw) + ')'

    def __str__(self):
        return "{ 'state': '" + str(self.state) + \
                "'\n'submission': " + str(self.submission) + \
                "\n'fileinfo': " + str(self.fileinfo) + \
                "\n'response': " + str(self.response) + \
                "\n'result': " + str(self.result)

