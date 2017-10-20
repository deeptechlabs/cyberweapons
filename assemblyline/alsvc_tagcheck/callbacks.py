"""
Please follow these guidelines when writing callbacks:
    -   All callbacks should import the following, in this order, at minimum (whether used or not):
        (request, result, sig_classification).
    -   Use try:except: for all module tasks.
    -   Write a description of what the callback does, as well as what a sample callback string should look like in a
        TagCheck signature.
    -   Arguments can be passed to callbacks by using ':' to separate callback location. Please see add_tag callback for
        example.
"""
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT
import logging

log = logging.getLogger('assemblyline.svc.tagcheck.callbacks')


def add_tag(request, result, sig_classification, args):
    """Will add a defined AL Tag to result set. Expected args is a tag type:tag value string
    Example callback in signature 'al_services.alsvc_tagcheck.callbacks.add_tag:TECHNIQUE_KEYLOGGER:TypeXYZ'"""
    try:
        tag_type = args.split(':', 1)[0]
        tag_value = args.split(':', 1)[1]
        result.add_tag(TAG_TYPE[tag_type], tag_value, TAG_WEIGHT['NULL'], classification=sig_classification)
    except Exception as e:
        log.debug("add_tag callback attempt failed", e)
