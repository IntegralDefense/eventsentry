import unittest

from lib.constants import HOME_DIR
from critsapi.critsapi import CRITsAPI
from critsapi.critsdbapi import CRITsDBAPI
import configparser
import os
import subprocess
import sys

class CritsApiTestCase(unittest.TestCase):
    """ Tests for critsapi. """

    def test_critsapi_connection(self):
        class WritableObject:
            def __init__(self):
                self.content = []
            def flush(self):
                pass
            def write(self, string):
                self.content.append(string)

        # Hijack the stdout
        hijack_stdout = WritableObject()
        orig_stdout = sys.stdout
        sys.stdout = hijack_stdout

        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        config = configparser.ConfigParser()
        config.read(config_path)

        os.environ['http_proxy'] = ''
        os.environ['https_proxy'] = ''

        api_url = config.get('production', 'crits_api_url')
        cert = config.get('production', 'verify_requests_cert')
        api_key = config.get('production', 'crits_api_key')
        api_user = config.get('production', 'crits_api_user')
        crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=cert)
        result = crits_api.get_object('5b800a6cad951d2daaaaaaaa', 'Indicator')

        # Restore stdout
        sys.stdout = orig_stdout

        if 'was: 401' in ''.join(hijack_stdout.content):
            self.fail('Check your critsapi username/key in: {}'.format(config_path))
        self.assertTrue('was: 404' in ''.join(hijack_stdout.content))

    def test_critsapi_mongo(self):
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        config = configparser.ConfigParser()
        config.read(config_path)

        mongo_uri = config.get('production', 'crits_mongo_url')
        mongo_db = config.get('production', 'crits_mongo_db')
        mongo_connection = CRITsDBAPI(mongo_uri=mongo_uri, db_name=mongo_db)
        mongo_connection.connect()
        indicators = list(mongo_connection.find_all('indicators')) 
        self.assertTrue(indicators)
