SUBMISSION_TEMPLATE = {
    "classification": "",
    "error_count": 0,
    "errors": [],
    "file_count": 0,
    "files": [],
    "results": [],
    "services": {
        "excluded": [],
        "selected": [
            "Antivirus",
            "Extraction",
            "Filtering",
            "Networking",
            "Static Analysis"
        ]
    },
    "state": "completed",
    "submission": {
        "deep_scan": False,
        "description": "Mock: %s",
        "groups": ["MOCK"],
        "ignore_cache": False,
        "ignore_filtering": False,
        "ignore_tag": False,
        "max_score": 0,
        "metadata": {
            "field": "value",
            "field_int": 1,
            "field_list": [1, "2"]
        },
        "params": {},
        "priority": 100,
        "sid": "",
        "submitter": "mock",
        "ttl": 1
    },
    "times": {
        "completed": "",
        "submitted": ""
    }
}

RESULT_TEMPLATE = {
    "classification": "",
    "created": "",
    "response": {
        "extracted": [],
        "message": "",
        "milestones": {
            "service_completed": 0,
            "service_started": 0
        },
        "service_debug_info": "serviced_on:127.0.0.1",
        "service_name": "Mock_%s",
        "service_version": "3.0.1.43754ec",
        "supplementary": []
    },
    "result": {
        "classification": "",
        "context": None,
        "default_usage": None,
        "score": 0,
        "sections": [],
        "tags": [],
        "tags_score": 0,
        "truncated": False
    },
    "srl": ""
}

RESULT_SECTION_TEMPLATE = {
    "body": "",
    "body_format": None,
    "classification": "",
    "depth": 0,
    "finalized": True,
    "links": [],
    "score": 0,
    "subsections": [],
    "title_text": "",
    "truncated": False
}

RESULT_TAG_TEMPLATE = {
    "classification": "",
    "context": None,
    "type": "",
    "usage": "IDENTIFICATION",
    "value": "",
    "weight": 1
}

FILE_TEMPLATE = {
    "ascii": "",
    "classification": "",
    "entropy": 0,
    "hex": "",
    "magic": "Mock file",
    "md5": "",
    "mime": "application/mock",
    "seen_count": 0,
    "seen_first": "",
    "seen_last": "",
    "sha1": "",
    "sha256": "",
    "size": 0,
    "tag": "fake/mock"
}
