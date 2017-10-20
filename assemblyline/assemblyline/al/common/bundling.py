
import json
import os
import subprocess
import time
import uuid

import shutil

from assemblyline.al.common import forge

config = forge.get_config()
Classification = forge.get_classification()
FILESTORE = forge.get_filestore()
MAX_RETRY = 10
STORAGE = forge.get_datastore()
WORK_DIR = "/tmp/bundling"


class BundlingException(Exception):
    pass


class SubmissionNotFound(Exception):
    pass


class IncompleteBundle(Exception):
    pass


class SubmissionAlreadyExist(Exception):
    pass


# noinspection PyBroadException
def format_result(r):
    try:
        title = r['result']['sections'][0]['title_text']
        if title.startswith('Result exceeded max size.'):
            sha256 = r['response']['supplementary'][-1][1]
            with forge.get_filestore() as transport:
                oversized = json.loads(transport.get(sha256))
            oversized['oversized'] = True
            return oversized
    except:  # pylint:disable=W0702
        pass

    return r


def get_results(keys, file_infos_p):
    out = {}
    res = {}
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        res.update(STORAGE.get_results_dict(keys))
        keys = [x for x in keys if x not in res]
        retry += 1

    results = {}
    for k, v in res.iteritems():
        file_info = file_infos_p.get(k[:64], None)
        if file_info:
            v = format_result(v)
            if v:
                results[k] = v

    out["results"] = results
    out["missing_result_keys"] = keys

    return out


def get_errors(keys):
    out = {}
    err = {}
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        err.update(STORAGE.get_errors_dict(keys))
        keys = [x for x in keys if x not in err]
        retry += 1

    out["errors"] = err
    out["missing_error_keys"] = keys

    return out


def get_file_infos(keys):
    infos = {}
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        infos.update(STORAGE.get_files_dict(keys))
        keys = [x for x in keys if x not in infos]
        retry += 1

    return infos


def recursive_flatten_tree(tree):
    srls = []

    for key, val in tree.iteritems():
        srls.extend(recursive_flatten_tree(val.get('children', {})))
        if key not in srls:
            srls.append(key)

    return list(set(srls))


# noinspection PyBroadException
def create_bundle(sid, working_dir=WORK_DIR):
    current_working_dir = os.path.join(working_dir, sid)
    try:
        submission = STORAGE.get_submission(sid)
        if submission is None:
            raise SubmissionNotFound("Can't find submission %s, skipping." % sid)
        else:
            target_file = os.path.join(working_dir, "%s.tgz" % sid)

            try:
                os.makedirs(current_working_dir)
            except:
                pass

            # Create file information data
            file_tree = STORAGE.create_file_tree(submission)
            flatten_tree = recursive_flatten_tree(file_tree)
            file_infos = get_file_infos(flatten_tree)

            # Add bundling metadata
            if 'al_originate_from' not in submission['submission']['metadata']:
                submission['submission']['metadata']['al_originate_from'] = config.ui.fqdn
                submission['submission']['metadata']['al_original_classification'] = submission['classification']

            data = {
                'submission': submission,
                'files': {"list": flatten_tree, "tree": file_tree, "infos": file_infos},
                'results': get_results(submission.get("results", []), file_infos),
                'errors': get_errors(submission.get("errors", []))
            }

            # Save result files
            with open(os.path.join(current_working_dir, "results.json"), "wb") as fp:
                json.dump(data, fp)

            # Download all related files
            for srl in flatten_tree:
                FILESTORE.download(srl, os.path.join(current_working_dir, srl))

            # Create the bundle
            subprocess.check_call("tar czf %s *" % target_file, shell=True, cwd=current_working_dir)

            return target_file

    except Exception as e:
        raise BundlingException("Could not bundle submission '%s'. [%s: %s]" % (sid, type(e).__name__, e.message))
    finally:
        if current_working_dir:
            subprocess.check_call(["rm", "-rf", current_working_dir])


# noinspection PyBroadException,PyProtectedMember
def import_bundle(path, working_dir=WORK_DIR, min_classification=Classification.UNRESTRICTED):
    current_working_dir = os.path.join(working_dir, str(uuid.uuid4()))
    res_file = os.path.join(current_working_dir, "results.json")
    try:
        os.makedirs(current_working_dir)
    except:
        pass

    # Extract  the bundle
    subprocess.check_call(["tar", "-zxf", path, "-C", current_working_dir])
    with open(res_file, 'rb') as fh:
        data = json.load(fh)

    submission = data['submission']
    results = data['results']
    files = data['files']
    errors = data['errors']

    try:
        sid = submission['submission']['sid']
        # Check if we have all the service results
        for res_key in submission['results']:
            if res_key not in results['results'].keys():
                raise IncompleteBundle("Incomplete results in bundle. Skipping %s..." % sid)

        # Check if we have all files
        for srl in list(set([x[:64] for x in submission['results']])):
            if srl not in files['infos'].keys():
                raise IncompleteBundle("Incomplete files in bundle. Skipping %s..." % sid)

        # Check if we all errors
        for err_key in submission['errors']:
            if err_key not in errors['errors'].keys():
                raise IncompleteBundle("Incomplete errors in bundle. Skipping %s..." % sid)

        if STORAGE.get_submission(sid):
            raise SubmissionAlreadyExist("Submission %s already exists." % sid)

        # Make sure bundle's submission meets minimum classification and save the submission
        submission['classification'] = Classification.max_classification(submission['classification'],
                                                                         min_classification)
        submission.update(Classification.get_access_control_parts(submission['classification']))
        STORAGE.save_submission(sid, submission)

        # Make sure files meet minimum classification and save the files
        for f, f_data in files['infos'].iteritems():
            f_classification = Classification.max_classification(f_data['classification'], min_classification)
            STORAGE.save_or_freshen_file(f, f_data, f_data['__expiry_ts__'], f_classification)

        # Make sure results meet minimum classification and save the results
        for key, res in results['results'].iteritems():
            if key.endswith(".e"):
                key = key[:-2]
            srl, service_name, version, srv_config = key.split('.')
            res_classification = Classification.max_classification(res['classification'], min_classification)
            STORAGE.save_result(service_name, version[1:], srv_config[1:], srl, res_classification, res)
            FILESTORE.put(os.path.join(current_working_dir, srl), srl)

        # Make sure errors meet minimum classification and save the errors
        for ekey, err in errors['errors'].iteritems():
            STORAGE._save_bucket_item(STORAGE.errors, ekey, err)

    finally:
        # Perform working dir cleanup
        try:
            os.remove(path)
        except:
            pass

        try:
            shutil.rmtree(current_working_dir, ignore_errors=True)
        except:
            pass
