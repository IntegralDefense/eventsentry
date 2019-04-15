import ace_api
from ace_api import Alert, AlertSubmitException

from lib.config import config

ace_api.set_default_remote_host(config.get('production', 'ace_api_server'))

if config.getboolean('production', 'ace_api_verify'):
    ace_api.default_ssl_verification = config.getboolean('production', 'ace_api_verify')

    if config.get('production', 'ace_api_verify_cert', fallback=None):
        ace_api.default_ssl_verification = config.get('production', 'ace_api_verify_cert')
else:
    ace_api.default_ssl_verification = False

