from assemblyline.common.importing import module_attribute_by_name
from al_services.alsvc_configdecoder import configparser

class GenericParser(configparser.ConfigParser):
    NAME = "Generic"

    def parse(self, request, hits, content):
        parsed_configs = []

        for func_name in set(x.meta.get('al_configdumper', None) for x in hits):
            if not func_name:
                continue

            name = func_name.split('.')[-2]
            parsed = None

            try:
                config = module_attribute_by_name(func_name)(content)
                if not config:
                    parsed = configparser.NullParsedConfig(self, name=name)
                else:
                    parsed = configparser.ParsedConfig(self, "1.0", name=name)
                    for k, v in config.iteritems():
                        parsed.add_value(k, v)
            except: # pylint: disable=W0702
                request._svc.log.exception("Problem with %s:", func_name)
                parsed = configparser.ParsedConfig(self, "1.0", name=name)

            parsed_configs.append(parsed)

        return parsed_configs

