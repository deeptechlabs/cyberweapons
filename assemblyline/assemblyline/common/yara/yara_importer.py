
import os
import logging

from assemblyline.common import isotime
from assemblyline.al.common import forge


class YaraImporter(object):
    REQUIRED_META = ['description', 'id', 'organisation', 'poc', 'rule_version', 'yara_version', 'rule_group']

    def __init__(self, logger=None):
        if not logger:
            from assemblyline.al.common import log as al_log
            al_log.init_logging('yara_importer')
            logger = logging.getLogger('assemblyline.yara_importer')
            logger.setLevel(logging.INFO)

        yara_parser_class = forge.get_yara_parser()
        self.ds = forge.get_datastore()
        self.yp = yara_parser_class()
        self.log = logger
        self._id_cache = {}
        self._name_cache = []

    def _get_next_id(self, org):
        if org in self._id_cache:
            self._id_cache[org] += 1
        else:
            self._id_cache[org] = self.ds.get_last_signature_id(org) + 1

        return self._id_cache[org]

    # noinspection PyMethodMayBeStatic
    def translate_rule(self, rule):
        return rule

    def display_rule(self, rule):
        return self.yp.dump_rule_file([rule], fake_dependencies=True)

    def display_rules(self, rules):
        return self.yp.dump_rule_file(rules, fake_dependencies=True)

    def import_now(self, rules):
        failed_list = []
        for rule in rules:
            validation_error = rule.get('validation_error', None)
            if validation_error:
                failed_list.append((rule['name'], "Previously failed rule validation (%s)" % validation_error))
                continue

            if rule['meta']['id'] == "<AUTO_INCREMENT>":
                rule['meta']['id'] = "%s_%06d" % (rule['meta']['organisation'],
                                                  self._get_next_id(rule['meta']['organisation']))
            if rule['meta']['rule_version'] == "<AUTO_INCREMENT>":
                rule['meta']['rule_version'] = self.ds.get_last_rev_for_id(rule['meta']['id'])

            if rule.get('is_new_revision', False):
                del rule['is_new_revision']
                new_id, new_rev = self.ds.get_next_rev_for_name(rule['meta']['organisation'], rule['name'])
                if new_id is not None and new_rev is not None:
                    rule['meta']['id'], rule['meta']['rule_version'] = new_id, new_rev
                else:
                    failed_list.append((rule['name'], "Could not find matching rule to increment revision number."))
                    continue

            key = "%sr.%s" % (rule['meta']['id'], rule['meta']['rule_version'])
            yara_version = rule['meta'].get('yara_version', None)
            rule['meta']['creation_date'] = isotime.now_as_iso()
            rule['meta']['last_saved_by'] = rule['meta']['al_imported_by']
            rule['depends'], rule['modules'] = self.yp.parse_dependencies(rule['condition'],
                                                                          self.yp.YARA_MODULES.get(yara_version, None))
            res = self.yp.validate_rule(rule)
            if res['valid']:
                rule['warning'] = res.get('warning', None)
                self.ds.save_signature(key, rule)
                self.log.info("Added signature %s" % rule['name'])
            else:
                failed_list.append((rule['name'], "Failed rule validation (%s)" % res['message']['error']))

        return failed_list

    def validate_rule(self, rule):
        return self.yp.validate_rule(rule)

    # noinspection PyBroadException
    def validate(self, field, value, rule):
        if not value:
            return False, "%s cannot be empty." % field
        elif field == "name":
            if " " in value:
                return False, "There should be no space in the name."
        elif field == "yara_version":
            if value not in self.yp.VALID_YARA_VERSION:
                return False, "yara_version should be one of the following: %s" % ", ".join(self.yp.VALID_YARA_VERSION)
        elif field == "rule_version":
            try:
                int(value)
            except:
                return False, "rule_version should be a simple integer value"
        elif field == "rule_group":
            if value not in self.yp.RULE_GROUPS:
                return False, "rule_group should be one of the following: %s" % ", ".join(self.yp.RULE_GROUPS)
        elif field == "organisation":
            if value != value.upper():
                return False, "organisation should be in all CAPS."
        elif field == "id":
            if not value == "<AUTO_INCREMENT>":
                try:
                    org, num = value.split("_")
                    if len(num) != 6:
                        error = True
                    elif org != rule['meta']['organisation']:
                        error = True
                    else:
                        int(num)
                        error = False
                except:
                    error = True

                if error:
                    return False, "id should have the following schema: ORG_000000"

        return True, ""

    def check_for_id_conflicts(self, rid, rev):
        if rid is None or rev is None:
            return False

        key = "%sr.%s" % (rid, rev)
        id_lookup = self.ds.get_signature(key)
        if id_lookup:
            return True

        return False

    def check_for_name_conflicts(self, name):
        try:
            name_lookup = self.ds.search_signature(query="name:%s" % name, rows=0)
            if name_lookup['total'] > 0:
                return True

            if name in self._name_cache:
                return True
            return False
        finally:
            self._name_cache.append(name)

    def parse_data(self, yara_bin, force_safe_str=False):
        output = []
        parsed_rules = self.yp.parse_rule_file(yara_bin, force_safe_str=force_safe_str)
        for rule in parsed_rules:
            missing_meta = []
            for item in self.REQUIRED_META:
                if item not in rule['meta']:
                    missing_meta.append(item)

            id_conflict = self.check_for_id_conflicts(rule['meta'].get('id', None),
                                                      rule['meta'].get('rule_version', None))

            name_conflict = self.check_for_name_conflicts(rule['name'])

            output.append({'rule': rule,
                           "missing_meta": sorted(missing_meta, reverse=True),
                           "id_conflict": id_conflict,
                           "name_conflict": name_conflict})
        return output

    def parse_file(self, cur_file, force_safe_str=False):
        cur_file = os.path.expanduser(cur_file)
        if os.path.exists(cur_file):
            with open(cur_file, "rb") as yara_file:
                yara_bin = yara_file.read()
                return self.parse_data(yara_bin, force_safe_str=force_safe_str)
        else:
            raise Exception("File '%s' does not exists.")

    def parse_files(self, files, force_safe_str=False):
        output = {}
        for cur_file in files:
            try:
                output[cur_file] = self.parse_file(cur_file, force_safe_str=force_safe_str)
            except Exception, e:
                output[cur_file] = e
        return output
