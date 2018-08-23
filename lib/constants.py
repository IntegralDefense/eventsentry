import os

HOME_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
PROXYCHAINS_CONFIG = os.path.realpath(os.path.join(HOME_DIR, 'etc', 'local', 'proxychains.conf'))
PROXYCHAINS = "http_proxy='' && https_proxy='' && " + os.path.realpath(os.path.join(HOME_DIR, 'bin', 'proxychains-ng', 'proxychains4'))
SPLUNKLIB = os.path.realpath(os.path.join(HOME_DIR, 'bin', 'splunklib', 'splunk.py'))
GETITINTOCRITS = os.path.realpath(os.path.join(HOME_DIR, 'bin', 'getitintocrits', 'bin', 'getitintocrits.py'))
BUILD_RELATIONSHIPS = os.path.realpath(os.path.join(HOME_DIR, 'bin', 'getitintocrits', 'bin', 'build_relationships.py'))
