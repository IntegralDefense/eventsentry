import ace_api
import os
from ace_api import Alert, AlertSubmitException

from lib.config import config

ace_api.set_default_remote_host(config['ace']['ace_api_server'])

if config['network']['verify_requests']:
    ace_api.default_ssl_verification = config['network']['verify_requests']

    if os.path.exists('/certificate'):
        ace_api.default_ssl_verification = '/certificate'
else:
    ace_api.default_ssl_verification = False

