#!/usr/bin/env python

import copy
import hashlib
import random
import sys
import uuid

from binascii import hexlify

from assemblyline.common.charset import dotdump
from assemblyline.common.isotime import now_as_iso, now
from assemblyline.al.bench.templates import SUBMISSION_TEMPLATE, RESULT_SECTION_TEMPLATE, \
    RESULT_TAG_TEMPLATE, RESULT_TEMPLATE, FILE_TEMPLATE
from assemblyline.al.common import forge

Classification = forge.get_classification()
config = forge.get_config()
ALPHA_NUMS = [chr(x + 65) for x in xrange(26)] + [chr(x + 97) for x in xrange(26)] + [str(x) for x in xrange(10)]


def generate_random_words(num_words):
    return " ".join(["".join([random.choice(ALPHA_NUMS)
                              for _ in xrange(int(random.random() * 10) + 2)])
                     for _ in xrange(num_words)])


def create_fake_result(svc_id, classification, srl, hours_to_live):
    start = now()
    # Generate a random configuration key
    length = int(random.random() * 32) + 32
    conf_bytes = "".join([chr(int(random.random() * 256)) for _ in xrange(length)])
    conf_key = hashlib.md5(conf_bytes).hexdigest()[:7]

    # Update result object with random values
    res_obj = copy.deepcopy(RESULT_TEMPLATE)
    res_obj['__expiry_ts__'] = now_as_iso(hours_to_live * 60 * 60)
    res_obj['created'] = now_as_iso()
    res_obj['response']['service_name'] %= svc_id
    res_obj['classification'] = res_obj['result']['classification'] = classification
    res_obj['srl'] = srl

    # Create result sections
    for _ in xrange(int(random.random() * 4) + 1):
        section = copy.deepcopy(RESULT_SECTION_TEMPLATE)
        section['classification'] = classification
        section['body'] = generate_random_words(int(random.random() * 1024) + 32)
        section['title_text'] = generate_random_words(int(random.random() * 14) + 2)
        res_obj['result']['sections'].append(section)

    # Create tags
    for _ in xrange(int(random.random() * 29) + 1):
        tag = copy.deepcopy(RESULT_TAG_TEMPLATE)
        tag['classification'] = classification
        tag['type'] = generate_random_words(1).upper()
        tag['value'] = generate_random_words(int(random.random() * 7) + 1)
        res_obj['result']['tags'].append(tag)

    # Update milestones
    res_obj['response']['milestones']['service_started'] = start
    res_obj['response']['milestones']['service_completed'] = now()
    return res_obj, conf_key


def create_fake_file():
    # generate a random file
    length = int(random.random() * 65535) + 256
    file_bytes = "".join([chr(int(random.random() * 256)) for _ in xrange(length)])

    # Update the file obj with the random data
    file_obj = copy.deepcopy(FILE_TEMPLATE)
    header = file_bytes[:min(64, length)]
    file_obj['ascii'] = dotdump(header)
    file_obj['hex'] = hexlify(header)
    file_obj['md5'] = hashlib.md5(file_bytes).hexdigest()
    file_obj['sha1'] = hashlib.sha1(file_bytes).hexdigest()
    file_obj['sha256'] = hashlib.sha256(file_bytes).hexdigest()
    file_obj['size'] = length
    file_obj['entropy'] = random.random() * 8
    file_obj['seen_first'] = now_as_iso()

    return file_obj


def create_fake_submission(current_ds, classification, file_count, res_per_file, hours_to_live):
    # Update the default submission with random values
    submission = copy.deepcopy(SUBMISSION_TEMPLATE)
    submission['times']['submitted'] = now_as_iso()
    submission['__expiry_ts__'] = now_as_iso(hours_to_live * 60 * 60)
    sid = str(uuid.uuid4())
    submission['submission']['sid'] = sid
    submission['submission']['description'] %= sid
    submission['file_count'] = file_count
    submission['classification'] = classification

    # Add files to the submissions
    for _ in xrange(file_count):
        file_obj = create_fake_file()
        current_ds.save_or_freshen_file(file_obj['sha256'],
                                        file_obj,
                                        now_as_iso(hours_to_live * 60 * 60),
                                        classification)
        submission['files'].append((file_obj['sha256'], file_obj['sha256']))

        # Add results to files
        for y in xrange(res_per_file):
            res_obj, config_key = create_fake_result(y, classification, file_obj['sha256'], hours_to_live)
            res_key = current_ds.save_result(res_obj['response']['service_name'],
                                             res_obj['response']['service_version'],
                                             config_key, file_obj['sha256'], classification, res_obj)
            submission['results'].append(res_key)

    submission['times']['completed'] = now_as_iso()
    current_ds.save_submission(sid, submission)

if __name__ == "__main__":
    # Initializing random picker
    classifications = [Classification.UNRESTRICTED, Classification.RESTRICTED]
    files = range(5)[1:]
    results = range(20)[1:]

    # Initializing datastore
    if len(sys.argv) < 3:
        print "usage: writer.py <hours_to_live> <datastore_ip_1> ... <datastore_ip_n>"
        exit(1)

    htl = 1
    try:
        htl = int(sys.argv[1])
    except ValueError:
        print "usage: writer.py <hours_to_live> <datastore_ip_1> ... <datastore_ip_n>"
        exit(1)

    ds_ip = sys.argv[2:]

    config.datastore.solr_port = 8093
    config.datastore.stream_port = 8098
    config.datastore.port = 8087
    config.datastore.hosts = ds_ip

    from assemblyline.al.core import datastore
    ds = datastore.RiakStore()

    # Creating fake submissions
    while True:
        create_fake_submission(ds, random.choice(classifications), random.choice(files), random.choice(results), htl)
