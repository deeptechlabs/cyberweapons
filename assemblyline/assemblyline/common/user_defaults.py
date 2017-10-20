
from assemblyline.al.common import forge

Classification = forge.get_classification()
config = forge.get_config()

SETTINGS_DEFAULT = {
    "classification": Classification.UNRESTRICTED,  # Default classification for the User's submissions
    "deep_scan": True,  # Should the system perform a deep scan or not
    "description": "",  # Default description for this user's submissions
    "download_encoding": config.ui.download_encoding,  # Default encoding for downloaded files
    "expand_min_score": 50,  # Default minimum score for results to be displayed in express mode
    "hide_raw_results": True,  # Hide result footer that can display raw results
    "ignore_cache": False,  # Should file be reprocessed even if there are cached results
    "ignore_filtering": False,  # Should filtering services by ignored?
    "ignore_tag": False,  # Should a file be send to all service?
    "profile": True,  # Should submissions be profiled
    "priority": 1000,  # Default submission priority
    "ttl": 15,  # Default time to live in days of the users submissions
    "service_spec": [],  # Default Service specific parameters
    "services": []  # Default list of selected services
}

ACCOUNT_DEFAULT = {
    "uname": "",  # Username
    "name": "",   # Full Name
    "avatar": None,  # Avatar of the user (optional: set to null if you don't have one)
    "groups": [],  # Groups the user is member of
    "is_admin": False,  # Is the user admin
    "is_active": True,  # Is the user active
    "classification": Classification.RESTRICTED,  # User's max classification
    "api_quota": 10,  # Maximum of simultaneous API calls
    "submission_quota": 5,  # Maximum of simultaneous Submissions in the system
    "agrees_with_tos": False,  # Date at which user agrees with Terms of Service
    "dn": None,  # Client Certificate DN
    "password": None,  # User's hashed password for default authenticator
    "otp_sk": None,  # One Time Password secret key
    "apikeys": [],  # List of APIKeys enabled on this account
    "u2f_devices": []  # List of registered u2f_devices
}

ACCOUNT_USER_MODIFIABLE = ["name", "avatar", "groups", "password"]
