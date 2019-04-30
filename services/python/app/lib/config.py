import os

from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

config_path = os.path.join('/eventsentry/app/conf/local/eventsentry.yml')
if not os.path.exists(config_path):
    raise FileNotFoundError('Unable to locate eventsentry.yml at: {}'.format(config_path))

with open(config_path) as c:
    config = load(c, Loader=Loader)

# This is a common enough pattern in the other files to just have it here instead.
if config['network']['verify_requests']:
    verify_requests = True

    # Now check if we want to use a custom CA cert to do so.
    if os.path.exists('/certificate'):
        verify_requests = '/certificate'
else:
    verify_requests = False
