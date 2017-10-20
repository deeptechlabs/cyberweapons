

##############################
# Locator functions
def srl_path(sha256):
    return "/" + "/".join([sha256[0], sha256[1], sha256[2], sha256[3], sha256])


def srl_dir(sha256):
    return "/" + "/".join([sha256[0], sha256[1], sha256[2], sha256[3]])
