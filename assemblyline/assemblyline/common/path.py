import os
import sys


def modulepath(modulename):
    m = sys.modules[modulename]
    f = getattr(m, '__file__', None)
    if not f:
        return os.path.abspath(os.getcwd())
    return os.path.dirname(os.path.abspath(f))


def splitpath(path, sep=None):
    """ Split the path into a list of items """
    return filter(len, path.split(sep or os.path.sep))


ASCII_NUMBERS = range(48, 58)
ASCII_UPPER_CASE_LETTERS = range(65, 91)
ASCII_LOWER_CASE_LETTERS = range(97, 123)
ASCII_OTHER = [45, 46, 92]  # "-", ".", and "\"

# Create a set that contains all of the valid characters that
# are allowed to appear in a Unified Naming Convention (UNC) path.
VALID_UNC_CHARS = [chr(x) for x in ASCII_LOWER_CASE_LETTERS +
                   ASCII_UPPER_CASE_LETTERS + ASCII_NUMBERS + ASCII_OTHER]


# noinspection PyPep8Naming
def isUNCLegal(path):
    """Determine whether or not a given string representing a Windows file path is legal
    or not as per the Unified Naming Convention (UNC) specifications."""
    if len(path) <= 0:
        return False

    for char in path:
        if char not in VALID_UNC_CHARS:
            return False
    return True


def test_main():
    inputs = [
        '',
        '/',
        'hello',
        '/hello',
        '//hello',
        'hello/'
        '/hello/world',
        'hello/world',
        './hello/world/',
        '../../hello/world/there',
    ]
    for testpath in inputs:
        print "[%s]->%s" % (testpath, splitpath(testpath))


if __name__ == '__main__':
    test_main()
