
import copy

from assemblyline.common.isotime import now_as_iso

ERROR_MAP = {
    "c502020e499f01f230e06a58ad9b5dcc": ("Max retries exceeded.", "FAIL_NONRECOVERABLE"),
    "d0591b2ced7c98928b8c59c168670a86": ("Task was pre-empted (shutdown, vm revert or cull)", "FAIL_RECOVERABLE"),
    "b54dc2e040a925f84e55e91ff27601ad": ("Service down.", "FAIL_NONRECOVERABLE"),
    "56d398ad9e9c4de4dd0ea8897073d430": ("Max depth exceeded.", "FAIL_NONRECOVERABLE"),
    "ae4dcce1b2fcc4f2ffa14195d1e8e866": ("Service busy.", "FAIL_NONRECOVERABLE"),
    "6e34a5b7aa6fbfb6b1ac0d35f2c44d70": ("Max files exceeded.", "FAIL_NONRECOVERABLE"),
}

ERROR_TEMPLATE = {
    "__access_grp1__": [],
    "__access_grp2__": [],
    "__access_lvl__": 100,
    "__access_req__": [],
    "created": None,
    "response": {
        "extracted": [],
        "message": None,
        "service_name": None,
        "service_version": None,
        "status": None,
        "supplementary": []
    },
    "result": []
}


def get_error_template_from_key(key):
    error_flag = key[-34:-32]
    ehash = key[-32:]
    if error_flag == ".e" and ehash in ERROR_MAP:
        temp = copy.deepcopy(ERROR_TEMPLATE)
        msg, status = ERROR_MAP[ehash]
        temp['response']['message'] = msg
        temp['response']['status'] = status
        temp['response']['service_name'] = key.split(".")[1]
        temp['created'] = now_as_iso()
        return temp
    else:
        return None


def is_template_error(key):
    error_flag = key[-34:-32]
    ehash = key[-32:]
    if error_flag == ".e" and ehash in ERROR_MAP:
        return True
    return False
