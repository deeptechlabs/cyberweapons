import easydict
import logging
import os
import riak
import time

from assemblyline.common.importing import module_attribute_by_name

SEED_BUCKET = 'blob'
SEED_KEY = os.environ.get('AL_SEED_KEY', '') or 'seed'
SEED_RIAK_NODE = os.environ.get('AL_DATASTORE', None) or '127.0.0.1'

seed = None


def _get_bucket(bucket_name=SEED_BUCKET):
    client = riak.RiakClient(nodes=[{'host': SEED_RIAK_NODE}])
    bucket = client.bucket(bucket_name, bucket_type="data")
    return bucket


def get_config(force_refresh=False, static_seed=os.getenv("AL_SEED_STATIC", None)):
    global seed  # pylint: disable=W0603
    if force_refresh or not seed:
        if static_seed:
            seed = easydict.EasyDict(module_attribute_by_name(static_seed))
        else:
            seed = easydict.EasyDict(load_seed())
    return seed


def load_profile(name):
    attempt = 0
    while True:
        try:
            bucket = _get_bucket('profile')
            data = bucket.get(name).data
            if not data:
                raise ValueError('Empty profile found.')
            return data
        except Exception as e:  # pylint: disable=W0703
            logging.error("Riak problem (%s). Retrying.\nError:%s", SEED_RIAK_NODE, str(e))
            attempt += 1
            if attempt >= 60:
                raise
            time.sleep(1)


def load_seed():
    attempt = 0
    while True:
        try:
            bucket = _get_bucket()
            current_seed = bucket.get(SEED_KEY).data
            if not current_seed:
                raise ValueError('Empty seed found.')
            return current_seed
        except Exception as e:  # pylint: disable=W0703
            logging.error("Riak problem (%s). Retrying.\n Error:%s", SEED_RIAK_NODE, str(e))
            attempt += 1
            if attempt >= 60:
                raise
            time.sleep(1)


def save_profile(name, data):
    attempt = 0
    while True:
        try:
            bucket = _get_bucket('profile')
            kv = bucket.new(key=name, data=data)
            kv.store()
            return
        except Exception as e:  # pylint: disable=W0703
            logging.error("Riak problem (%s). Retrying.\nError:%s", SEED_RIAK_NODE, str(e))
            attempt += 1
            if attempt >= 60:
                raise
            time.sleep(1)


def save_seed(current_seed, seed_name):
    attempt = 0
    while True:
        try:
            bucket = _get_bucket()
            kv = bucket.new(key=seed_name, data=current_seed)
            kv.store()
            return
        except Exception as e:  # pylint: disable=W0703
            logging.error("Riak problem (%s). Retrying.\nError:%s", SEED_RIAK_NODE, str(e))
            attempt += 1
            if attempt >= 60:
                raise
            time.sleep(1)
