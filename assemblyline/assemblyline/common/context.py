class Context(object):

    AFFECTS = 'Affects'
    COMPROMISED = 'Compromised'
    DERIVED_FROM = 'Derived From'
    DYNAMIC = 'Dynamic'
    IDENTIFIES = 'Identifies'
    STATIC = 'Static'
    PART_OF = 'Part Of'
    RESPONSIBLE_FOR = 'Responsible For'
    VARIANT_OF = 'Variant Of'
    COMMON_CONTEXT = [AFFECTS, COMPROMISED, DERIVED_FROM, DYNAMIC, IDENTIFIES, PART_OF, RESPONSIBLE_FOR, STATIC,
                      VARIANT_OF]

    BEACONS = 'Beacons'
    CONNECTS_TO = 'Connects To'
    DOWNLOADS = 'Downloads'
    LINKED_TO = 'Linked To'
    RESOLVES_TO = 'Resolves To'
    SENDS_TO = 'Sends To'
    SENT_AS_BCC_TO = 'Sent As BCC To'
    SENT_AS_CC_TO = 'Sent As CC To'
    SPOOFER_OF = 'Spoofer Of'
    NETWORKING_CONTEXT = [BEACONS, CONNECTS_TO, DOWNLOADS, LINKED_TO, RESOLVES_TO, SENDS_TO, SENT_AS_BCC_TO,
                          SENT_AS_CC_TO, SPOOFER_OF]

    CHILD_OF = 'Child Of'
    CONTAINS = 'Contains'
    OWNER_OF = 'Owner Of'
    USER_OF = 'User Of'
    FILE_CONTEXT = [CHILD_OF, CONTAINS, OWNER_OF, USER_OF]

    # List of allowed Tag to Context mappings
    # If not explicitly specified, COMMON_CONTEXT is defaulted for the tag
    RECOGNIZED_CONTEXT = {
        'AUTORUN_': COMMON_CONTEXT + FILE_CONTEXT,
        'DYNAMIC_': COMMON_CONTEXT + FILE_CONTEXT,
        'FILE_': COMMON_CONTEXT + FILE_CONTEXT,
        'FILENAME_': COMMON_CONTEXT + FILE_CONTEXT,
        'NET_': COMMON_CONTEXT + NETWORKING_CONTEXT,
        'PE_': COMMON_CONTEXT + FILE_CONTEXT,
        'REGISTRY_': COMMON_CONTEXT + FILE_CONTEXT,
        'SERVICE_': None,
        'TECHNIQUE_': COMMON_CONTEXT + FILE_CONTEXT + NETWORKING_CONTEXT,
        'HEURISTIC': None,
        'REQUEST_USERNAME': None,
        'REQUEST_SCORE': None,
        'DISPLAY_STRING_SEARCH': None,
    }

    STARTWITH_CONTEXT = {
        'AV_': ["scanner:"]
    }

    @staticmethod
    def verify_context(tag_type, test_context):
        # Check Recognized Context pairs first
        for key in Context.RECOGNIZED_CONTEXT.keys():
            if tag_type.startswith(key) and test_context in Context.RECOGNIZED_CONTEXT[key]:
                return True

        # Default to Common Context
        if test_context in Context.COMMON_CONTEXT:
            return True

        for key in Context.STARTWITH_CONTEXT.keys():
            if tag_type.startswith(key):
                for item in Context.STARTWITH_CONTEXT[key]:
                    if test_context.startswith(item):
                        return True

        return False
