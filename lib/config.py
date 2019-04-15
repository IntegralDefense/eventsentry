import configparser
import os

from lib.constants import HOME_DIR

config_path = os.path.join(HOME_DIR, 'etc/local/config.ini')
if not os.path.exists(config_path):
    raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
config = configparser.ConfigParser()
config.read(config_path, encoding='utf8')

