import importlib
import logging
import os

def run_all(event_json):
    logger = logging.getLogger()

    this_dir = os.path.dirname(__file__)
    modules = sorted(os.listdir(this_dir))

    for m in modules:
        if m.endswith('.py') and not '__init__' in m:
            name = m[:-3]
            try:
                module = importlib.import_module('lib.modules.indicators.{}'.format(name))
                mod = module.Module(name, event_json)
                mod.timed_run()
                event_json = mod.event_json
                logger.debug('{} indicator module {} runtime: {}'.format(event_json['name'], name, mod.runtime))
            except:
                logger.exception('Error running indicator module: {}'.format(name))

    return event_json
