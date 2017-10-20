from __future__ import print_function

import os
import shutil
from getpass import getpass

PASS_BASIC = [chr(x + 65) for x in xrange(26)] + \
             [chr(x + 97) for x in xrange(26)] + \
             [str(x) for x in xrange(10)] + \
             ["!", "@", "$", "%", "^", "?", "&", "*", "(", ")"]


def get_int(msg, min_val=None, max_val=None, default=None):
    while True:
        input_val = raw_input("%s%s: " % (msg, {True: "", False: " [%s]" % default}[default is None]))
        if input_val:
            try:
                int_input = int(input_val)
                if min_val is not None and int_input < min_val:
                    raise IndexError("%s is smaller then the minimum value %s." % (int_input, min_val))

                if max_val is not None and int_input > max_val:
                    raise IndexError("%s is bigger then the maximum value %s." % (int_input, max_val))

                return int_input

            except ValueError:
                print("Input is not an Integer: %s" % input_val)
            except IndexError, e:
                print(e.message)
        else:
            if default:
                return default


def get_float(msg, min_val=None, max_val=None, default=None):
    while True:
        input_val = raw_input("%s%s: " % (msg, {True: "", False: " [%s]" % default}[default is None]))
        if input_val:
            try:
                float_input = float(input_val)
                if min_val is not None and float_input < min_val:
                    raise IndexError("%s is smaller then the minimum value %s." % (float_input, min_val))

                if max_val is not None and float_input > max_val:
                    raise IndexError("%s is bigger then the maximum value %s." % (float_input, max_val))

                return float_input

            except ValueError:
                print("Input is not an Integer: %s" % input_val)
            except IndexError, e:
                print(e.message)
        else:
            if default:
                return default


def get_string_list(msg, validator=None):
    value = get_string(msg, validator=validator)
    return [item.strip() for item in value.split(",")]


def get_string(msg, validator=None, default=None):
    while True:
        if default:
            str_val = raw_input("%s [%s]: " % (msg, default))
            if not str_val:
                str_val = default
        else:
            str_val = raw_input("%s: " % msg)

        if not str_val:
            continue

        if validator is not None:
            validation_error = validator(str_val)
            if validation_error is None:
                return str_val
            else:
                print(validation_error)
        else:
            return str_val


def get_password(msg, default=None):
    while True:
        if default:
            str_val = getpass("%s [%s]: " % (msg, default))
            if not str_val:
                return default
        else:
            str_val = getpass("%s: " % msg)
            if not str_val:
                print("You need to type a password...")
                continue

        validation = getpass("Re-type the same password: ")
        if validation == str_val:
            return str_val


def get_bool(msg, default=True):
    while True:
        if default:
            bool_val = raw_input("%s [Y/n] " % msg).lower()
        else:
            bool_val = raw_input("%s [y/N] " % msg).lower()

        if not bool_val:
            return default

        if bool_val == "y":
            return True

        if bool_val == "n":
            return False


def get_random_password(alphabet=PASS_BASIC, length=24):
    r_bytes = bytearray(os.urandom(length))
    a_list = []

    for byte in r_bytes:
        while byte >= (256 - (256 % len(alphabet))):
            byte = ord(os.urandom(1))
        a_list.append(alphabet[byte % len(alphabet)])

    return "".join(a_list)


def pick_from_list(msg, items):
    if len(items) < 1:
        raise Exception("Not enough items in selection list")

    display_msg = "\n"
    for idx, item in enumerate(items):
        display_msg += "\t%s. %s\n" % (idx + 1, item)

    display_msg += "\n%s\n" % msg

    while True:
        input_val = raw_input(display_msg)
        if not input_val:
            continue

        try:
            input_val = int(input_val) - 1
            if 0 <= input_val <= len(items) - 1:
                return items[input_val]
        except ValueError:
            pass

        print("%s is not a valid selection." % (input_val + 1))


def ip_list_validator(value):
    items = value.split(",")

    for item in items:
        item = item.strip()
        error = ip_validator(item)
        if error is not None:
            return error

    return None


def ip_validator(value):
    try:
        octets = value.split(".")
        if len(octets) != 4:
            return "Invalid IP: %s" % value

        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return "Invalid IP: %s" % value

        return None
    except ValueError:
        return "Invalid IP: %s" % value


def path_exits_validator(path):
    if os.path.exists(path):
        working_dir = os.path.join(path, 'al_private')
        if os.path.exists(working_dir):
            if get_bool("%s already exists. Do you want to override it? " % working_dir, default=False):
                shutil.rmtree(working_dir)
            else:
                return "Choose a different path to continue..."
        return None
    return "Path does not exists: %s" % path
