
from assemblyline.common.importing import class_by_name


def get_merged_svc_config(name, configuration, log):
    classpath = configuration.get('classpath',
                                  "al_services.%s.%s" % (configuration['repo'], configuration['class_name']))
    if 'config' in configuration:
        config_overrides = configuration.pop('config')
    else:
        config_overrides = {}

    if 'classpath' not in configuration:
        configuration['classpath'] = classpath

    # noinspection PyBroadException
    try:
        cls = class_by_name(classpath)
        if not hasattr(cls, "get_default_config"):
            log.error(name + " is not an AL service. Make sure the class path you've entered is valid.")
            return configuration
    except:
        # log.error(classpath + " could not be found. Make sure the class path you've entered is valid.")
        configuration['config'] = config_overrides
        return configuration

    cfg = cls.get_default_config()
    cfg.update(configuration)

    if config_overrides:
        for cfg_key, cfg_value in config_overrides.iteritems():
            if cfg_key not in cfg['config'] and cfg_key != 'PLUMBER_MAX_QUEUE_SIZE':
                log.warn("Config override %s is not a valid configuration option for %s" % (cfg_key, name))
                continue
            cfg['config'][cfg_key] = cfg_value

    return cfg
