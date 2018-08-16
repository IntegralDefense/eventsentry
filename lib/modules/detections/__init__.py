import importlib
import logging
import os

def run_all(event_json):
    logger = logging.getLogger()

    tags = []
    detections = []
    extra = []

    this_dir = os.path.dirname(__file__)
    modules = sorted(os.listdir(this_dir))

    for m in modules:
        if m.endswith('.py') and not '__init__' in m:
            name = m[:-3]
            try:
                module = importlib.import_module('lib.modules.detections.{}'.format(name))
                mod = module.Module(name, event_json)
                mod.timed_run()
                tags += mod.tags
                detections += mod.detections
                extra += mod.extra
                logger.debug('{} detection module {} runtime: {}'.format(event_json['name'], name, mod.runtime))
            except:
                logger.exception('Error running detection module: {}'.format(name))

    tags = sorted(list(set(tags)))
    detections = sorted(list(set(detections)))
    extra = sorted(list(set(extra)))

    return tags, detections, extra
