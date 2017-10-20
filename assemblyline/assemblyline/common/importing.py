
import importlib
import sys


def apply_overlay(module_name, overlay):
    from assemblyline.common.charset import safe_str
    if not overlay:
        return False

    import sys
    module = sys.modules[module_name]

    for k, v in overlay.iteritems():
        t = type(v)
        if t == unicode or t == str:
            v = safe_str(v)

        setattr(module, k, v)

    return True


def apply_seed(module_name, seed):
    return apply_overlay(module_name, construct_overlay(module_name, seed))


def construct_overlay(module_name, seed):
    specification = seed.get('overlay', {}).get(module_name, {})
    return {
        k: module_attribute_by_name(v) for k, v in specification.iteritems()
        }


def module_attribute_by_name(name):
    module_path, _sep, module_attribute_name = name.rpartition('.')
    module = sys.modules.get(module_path, None)
    if not module:
        module = importlib.import_module(module_path)
    return getattr(module, module_attribute_name)


class_by_name = module_attribute_by_name
class_by_path = module_attribute_by_name
