#!/usr/bin/env python

import ConfigParser
import json
import os

from getpass import getuser
from optparse import OptionParser


__version__ = "Yara Importer v0.1"


class PrintLogger(object):
    def __init__(self):
        pass

    @staticmethod
    def info(message):
        print message

    @staticmethod
    def warning(message):
        print "WARNING: " + message

    @staticmethod
    def error(message):
        print "ERROR: " + message

    @staticmethod
    def exception(e):
        print "EXCEPTION: " + e.message


def get_field_value(field, cur_rule, cur_defaults, cur_actions, save_action=True):
    if cur_actions.get(field, None) == 'a':
        input_value = cur_defaults.get(field, None)
        if input_value:
            print "%s: %s" % (field, input_value)
    else:
        input_value = ""

    if not input_value:
        valid_field_value = False
        while not valid_field_value:
            if cur_defaults.get(field, None):
                input_value = raw_input("%s [%s]: " % (field, cur_defaults[field]))
            else:
                input_value = raw_input("%s: " % field)

            if input_value == "" or input_value is None:
                input_value = cur_defaults.get(field, "")

            valid_field_value, reason = yara_importer.validate(field, input_value, cur_rule)
            if not valid_field_value:
                print "\tERR: Invalid value! %s" % reason

        if save_action and not cur_actions.get(field, None) and len(missing_metas) > 1:
            valid_action_value = False
            while not valid_action_value:
                act = raw_input("\tApply to (a)ll, (o)ne by one or (e)nter a new value? [a] ")

                if act == "" or act is None:
                    act = "a"

                if act in ["o", "a"]:
                    cur_actions[field] = act
                    valid_action_value = True
                elif act == "e":
                    input_value = get_field_value(field, cur_rule, cur_defaults, cur_actions, save_action)
                    break
                else:
                    print "\t\tERR: Invalid value should be 'a' or 'o'."

    return input_value


def fix_metadata(p_rule_map, p_missing_metas, p_id_conflicts, p_defaults, p_actions, yar_imp):
    for rule_name in p_missing_metas:
        print "-- Fixing %s's metadata fields --" % rule_name.upper()
        valid_rule = False

        while not valid_rule:
            rule_result = p_rule_map[rule_name]
            rule = rule_result['rule']
            for meta in rule_result['missing_meta']:
                meta_value = get_field_value(meta, rule, p_defaults, p_actions)

                p_defaults[meta] = meta_value
                rule['meta'][meta] = meta_value.replace("<NAME>", rule_name)

            rule_group = rule['meta']['rule_group']
            if rule_group not in rule['meta']:
                rg_value = get_field_value(rule_group, rule, p_defaults, p_actions)
                p_defaults[rule_group] = rg_value
                rule['meta'][rule_group] = rg_value.replace("<NAME>", rule_name)

            if yar_imp.check_for_id_conflicts(rule['meta'].get('id', None), rule['meta'].get('rule_version', None)):
                if rule_name not in p_id_conflicts:
                    p_id_conflicts.append(rule_name)

            if options.verbose:
                print yar_imp.display_rule(rule)
                valid_response = False
                while not valid_response:
                    meta_value = raw_input("Ok? [y] ")
                    if meta_value == "" or meta_value == "y":
                        valid_response = valid_rule = True
                    elif meta_value == "n":
                        valid_response = True
                        p_actions = {}

            else:
                valid_rule = True

        print ""


def fix_id_conflicts(p_rule_map, p_id_conflicts, force_defaults=False):
    for rule_name in p_id_conflicts:
        print "-- Fixing id conflict for %s --" % rule_name.upper()
        rule_result = p_rule_map.get(rule_name, None)
        if not rule_result:
            continue

        rule = rule_result['rule']
        if rule.get('do_not_import', False):
            continue

        print "Current ID: %sr.%s" % (rule['meta']['id'], rule['meta']['rule_version'])

        valid_action_value = False
        while not valid_action_value:
            if force_defaults:
                act = None
            else:
                act = raw_input("\t This rule ID already exists in our system.\n\n"
                                "Do you want to [s]kip the rule, auto-increment it's "
                                "[r]evision number or auto-increment it's [i]d? [s] ")

            if act == "" or act is None:
                act = "s"

            if act in ["s", "r", "i"]:
                if act == "s":
                    del p_rule_map[rule_name]
                elif act == 'r':
                    rule['meta']['rule_version'] = "<AUTO_INCREMENT>"
                else:
                    rule['meta']['id'] = "<AUTO_INCREMENT>"
                valid_action_value = True
            else:
                print "\t\tERR: Invalid value should be 's', 'r' or 'i'."


def fix_name_conflicts(p_rule_map, p_name_conflicts, yar_imp, force_defaults=False):
    for rule_name in p_name_conflicts:
        print "-- Fixing name conflict for %s --" % rule_name.upper()
        rule_result = p_rule_map.get(rule_name, None)
        if not rule_result:
            continue

        rule = rule_result['rule']
        if rule.get('do_not_import', False):
            continue

        valid_action_value = False
        while not valid_action_value:
            if force_defaults:
                act = None
            else:
                act = raw_input("\t This rule name already exists in our system.\n\n"
                                "Do you want to [s]kip the rule, [c]hange it's name or [m]ark rule as new revision "
                                "of the current rule? [s] ")

            if act == "" or act is None:
                act = "s"

            if act in ["s", "c", "m"]:
                if act == "s":
                    del p_rule_map[rule_name]
                elif act == "m":
                    rule['is_new_revision'] = True
                else:
                    fixed = False
                    while not fixed:
                        new_name = get_field_value("name", rule, {}, {}, save_action=False)
                        rule['name'] = new_name

                        if not yar_imp.check_for_name_conflicts(new_name):
                            fixed = True
                            rule['name'] = new_name
                        else:
                            print "\tThere is still a conflict in the name..."
                valid_action_value = True
            else:
                print "\t\tERR: Invalid value should be 's' or 'c'."


def validate_rules(p_rule_map, yar_imp, p_defaults, p_actions):
    for r_name, rule_res in p_rule_map.iteritems():
        rule = rule_res['rule']
        print "\n** Validating %s rule **\n" % r_name.upper()
        rule['meta']['al_imported_by'] = rule['meta'].get('al_imported_by', getuser())
        validated = False
        while not validated:
            validation_results = yar_imp.validate_rule(rule)
            validated = validation_results['valid']
            if not validated:
                broken_field = validation_results.get('field', "")
                if broken_field:
                    print "ValidationError: Rule validator failed on " \
                          "field %s. (%s)" % (broken_field, validation_results['message'])
                    if 'meta.' in broken_field:
                        broken_field = broken_field.replace("meta.", "")
                        f_value = get_field_value(broken_field, rule, p_defaults, p_actions)

                        rule['meta'][broken_field] = f_value.replace("<NAME>", r_name)
                        p_defaults[broken_field] = f_value
                    else:
                        print "ImportError: Rule %s hit a non-recoverable error. " \
                              "This file will be skipped at import. (%s)" % (r_name.upper(),
                                                                             validation_results['message'])
                        rule['validation_error'] = validation_results['message']
                        validated = True
                else:
                    print "ImportError: Rule %s hit a non-recoverable error. " \
                          "This file will be skipped at import. (%s)" % (r_name.upper(),
                                                                         validation_results['message']['error'])
                    rule['validation_error'] = validation_results['message']['error']
                    validated = True


def wrapup(yar_imp, rules, store, outfile):
    if not store and not outfile:
        valid = False
        while not valid:
            value = raw_input("What do you want to do with your changes?\n([o]utput to file, "
                              "[p]rint to screen or [s]ave in AL): ")
            if value not in ["s", "o", "p"]:
                print "\tERR: Invalid value must be o, p or s."
            else:
                valid = True
                if value == "s":
                    failed_files = yar_imp.import_now(rules)

                    if not failed_files:
                        print "\n\nAll rules saved to AL!"
                    else:
                        print "\n\nSomething went wrong adding the following rules:"
                        for rname, reason in failed_files:
                            print "\t%s: %s" % (rname, reason)
                elif value == "p":
                    print "\n\n------------------\n\n"
                    print yar_imp.display_rules(rules)
                if value == "o":
                    saved = False
                    while not saved:
                        value = raw_input("Output file: ")
                        # noinspection PyBroadException
                        try:
                            outpath = os.path.expanduser(value)
                            with open(outpath, 'wb') as out_file:
                                out_file.write(yar_imp.display_rules(rules))
                            saved = True
                            print "\nValid rules saved to %s." % outpath
                        except:
                            print "\nCannot write to %s." % value
    elif store:
        failed_files = yar_imp.import_now(rules)

        if not failed_files:
            print "\n\nAll rules saved to AL!"
        else:
            print "\n\nSomething went wrong adding the following rules:"
            for rname, reason in failed_files:
                print "\t%s: %s" % (rname, reason)
    else:
        outpath = os.path.expanduser(outfile)
        with open(outpath, 'wb') as out_file:
            out_file.write(yar_imp.display_rules(rules))
        print "\n\nValid rules saved to %s." % outpath


# noinspection PyTypeChecker
def ask_before_continue(message, force_defaults=False):
    if force_defaults:
        return False
    my_input = raw_input(message + " Continue? [y/N] ")
    if my_input in ['y', 'Y']:
        return True
    elif my_input in ["n", "N"] or my_input == "" or my_input is None:
        return False
    else:
        return ask_before_continue(message, force_defaults=force_defaults)


if __name__ == "__main__":
    defaults = {
        'id': "<AUTO_INCREMENT>",
        "rule_version": "1",
        "implant": "<NAME>",
        "exploit": "<NAME>",
        "info": "<NAME>",
        "technique": "<NAME>",
        "tool": "<NAME>",
        "yara_version": "3.6"
    }
    actions = {}

    config = ConfigParser.ConfigParser()
    config.read([os.path.expanduser('~/.al/yara_importer.cfg')])
    for section in config.sections():
        for option in config.options(section):
            defaults[option] = config.get(section, option)

    usage = "usage: %prog [options] file1 file2 ... fileN"
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option("-f", "--force", action="store_true", dest="force_defaults", default=False,
                      help="Force usage of default values without prompting")
    parser.add_option("-u", "--utf8", action="store_true", dest="force_utf8", default=False,
                      help="Force utf8 encoding of everything")
    parser.add_option("-j", "--json", dest="json", help="Default json values")
    parser.add_option("-o", "--outfile", dest="outfile", help="Set output file")
    parser.add_option("-s", "--save", action="store_true", dest="store", default=False,
                      help="Store directly in AL")
    parser.add_option("-V", "--verbose", action="store_true", dest="verbose", default=False,
                      help="Verbose mode")
    (options, args) = parser.parse_args()

    if len(args) == 0:
        parser.print_help()
        exit(1)

    from assemblyline.al.common import forge
    YaraImporter = forge.get_yara_importer()

    yara_importer = YaraImporter(logger=PrintLogger())
    if options.json:
        temp_defaults = json.loads(options.json)
        if isinstance(temp_defaults, dict):
            defaults.update(temp_defaults)

    if options.force_defaults:
        for key in defaults:
            actions[key] = "a"

    parsed_files = yara_importer.parse_files(args, force_safe_str=options.force_utf8)
    for parsed_file, result in parsed_files.iteritems():
        if not options.force_defaults:
            actions = {}

        print "\n### %s ###\n" % parsed_file
        tba_metas = []
        missing_metas = []
        id_conflicts = []
        name_conflicts = []
        rule_map = {}

        # Gathering information on what needs to be done
        for rule_results in result:
            rule_results['rule'] = yara_importer.translate_rule(rule_results['rule'])
            name = rule_results['rule']['name']
            rule_map[name] = rule_results
            if len(rule_results['missing_meta']) > 0:
                missing_metas.append(name)
                tba_metas.extend(rule_results['missing_meta'])

            if rule_results['id_conflict']:
                id_conflicts.append(name)

            if rule_results['name_conflict']:
                name_conflicts.append(name)

        if len(id_conflicts) == len(rule_map.keys()):
            if not ask_before_continue("All IDs are in conflicts, you've most likely already imported that file.",
                                       force_defaults=options.force_defaults):
                print "File skipped because all IDs are already in the system."
                continue

        if len(name_conflicts) == len(rule_map.keys()):
            if not ask_before_continue("All rule names are in conflicts, "
                                       "you've most likely already imported that file.",
                                       force_defaults=options.force_defaults):
                print "File skipped because all rule names are already in the system."
                continue

        # Fixing missing metadata fields
        if len(missing_metas) > 0:
            print "[MISSING METADATA]"
            print "Some rules are missing metadata fields (%s rules):" % len(missing_metas)
            print "\t%s\n" % ", ".join(missing_metas)
            if options.verbose:
                print "These are the metadata fields generally missing:\n\t%s\n" % ", ".join(set(tba_metas))

            fix_metadata(rule_map, missing_metas, id_conflicts, defaults, actions, yara_importer)

        # Validate all rules
        print "[STRICT RULE VALIDATION]"
        validate_rules(rule_map, yara_importer, defaults, actions)

        # Fixing rule id conflicts
        if len(id_conflicts) > 0:
            print "[ID CONFLICT RESOLUTION]"
            print "Some rules have conflicting ids (%s rules):" % len(id_conflicts)
            print "\t%s\n" % ", ".join(id_conflicts)

            fix_id_conflicts(rule_map, id_conflicts, force_defaults=options.force_defaults)

        # Fixing name conflicts
        if len(name_conflicts) > 0:
            print "[NAME CONFLICT RESOLUTION]"
            print "Some rules have conflicting names (%s rules):" % len(name_conflicts)
            print "\t%s\n" % ", ".join(name_conflicts)

            fix_name_conflicts(rule_map, name_conflicts, yara_importer, force_defaults=options.force_defaults)

        # Changes are completed. Wrapping up...
        wrapup(yara_importer, [x['rule'] for x in rule_map.values()], options.store, options.outfile)
