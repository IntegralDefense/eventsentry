import configparser
import MySQLdb
import os
import subprocess
import sys
import unittest

from critsapi.critsapi import CRITsAPI
from critsapi.critsdbapi import CRITsDBAPI
from lib.constants import HOME_DIR
from lib.confluence.ConfluenceEventPage import ConfluenceEventPage

config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
config = configparser.ConfigParser()
config.read(config_path)

class ConfigTestCase(unittest.TestCase):
    """ Tests for etc/local/config.ini """

    ###################################
    ##                               ##
    ##  PATHS AND PERMISSIONS TESTS  ##
    ##                               ##
    ###################################

    def test_event_directory_exists(self):
        """ Make sure the parent event directory exists """

        self.assertTrue(os.path.exists(config.get('production', 'event_path_prefix')))

    def test_event_directory_permissions(self):
        """ Make sure the parent event directory is writable """

        self.assertTrue(os.access(config.get('production', 'event_path_prefix'), os.W_OK))

    def test_https_certificate_exists(self):
        """ Make sure the HTTPS verify certificate exists """

        path = config.get('production', 'verify_requests_cert', fallback=None)
        if path:
            self.assertTrue(os.path.exists(path))

    def test_https_certificate_permissions(self):
        """ Make sure the HTTPS verify certificate is readable """

        path = config.get('production', 'verify_requests_cert', fallback=None)
        if path:
            self.assertTrue(os.access(path, os.R_OK))

    ###################
    ##               ##
    ##  CRITS TESTS  ##
    ##               ##
    ###################

    def test_critsapi_connection(self):
        """ Make sure we can connect to CRITS """

        class WritableObject:
            def __init__(self):
                self.content = []
            def flush(self):
                pass
            def write(self, string):
                self.content.append(string)

        # Hijack the stdout since critsapi uses print().
        hijack_stdout = WritableObject()
        orig_stdout = sys.stdout
        sys.stdout = hijack_stdout

        os.environ['http_proxy'] = ''
        os.environ['https_proxy'] = ''

        # Search for a bogus indicator ID that we expect to not exist.
        verify = config.getboolean('production', 'verify_requests', fallback=False)
        cert = config.get('production', 'verify_requests_cert', fallback=None)
        api_url = config.get('production', 'crits_api_url')
        api_key = config.get('production', 'crits_api_key')
        api_user = config.get('production', 'crits_api_user')
        if verify and cert:
            crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=cert)
        elif verify and not cert:
            crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=verify)
        else:
            crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=False)
        result = crits_api.get_object('5b800a6cad951d2daaaaaaaa', 'Indicator')

        # Restore stdout
        sys.stdout = orig_stdout

        if 'was: 401' in ''.join(hijack_stdout.content):
            self.fail('Check your critsapi username/key in: {}'.format(config_path))
        self.assertTrue('was: 404' in ''.join(hijack_stdout.content))

    def test_critsapi_mongo(self):
        """ Make sure we can connect to the raw Mongo database """

        mongo_uri = config.get('production', 'crits_mongo_url')
        mongo_db = config.get('production', 'crits_mongo_db')
        mongo_connection = CRITsDBAPI(mongo_uri=mongo_uri, db_name=mongo_db)
        mongo_connection.connect()
        indicator = mongo_connection.find_one('indicators', {'status': 'Analyzed'})
        self.assertTrue(indicator)

    #################
    ##             ##
    ##  ACE TESTS  ##
    ##             ##
    #################

    def test_ace_ssh_connection(self):
        """ Make sure we can SSH to the ACE server and access the alert root directory """

        ace_server = config.get('production', 'ace_server')
        ace_ssh_user = config.get('production', 'ace_ssh_user')
        ace_ssh_key = config.get('production', 'ace_ssh_key')
        ace_alert_root = config.get('production', 'ace_alert_root')

        ssh_command = 'ssh -i {} {}@{} "ls {}"'.format(ace_ssh_key, ace_ssh_user, ace_server, ace_alert_root)
        subprocess.check_call(ssh_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

    def test_ace_db_connection(self):
        """ Make sure we can access the ACE MySQL database """

        ace_db_server = config.get('production', 'ace_db_server')
        ace_db_user = config.get('production', 'ace_db_user')
        ace_db_pass = config.get('production', 'ace_db_pass')
        ace_db_name = config.get('production', 'ace_db_name')
        db = MySQLdb.connect(host=ace_db_server, user=ace_db_user, passwd=ace_db_pass, db=ace_db_name)
        c = db.cursor()
        c.close()
        db.close()

    ########################
    ##                    ##
    ##  CONFLUENCE TESTS  ##
    ##                    ##
    ########################

    def test_confluence_connection(self):
        """ Make sure we can connect to Confluence and edit pages """

        wiki = ConfluenceEventPage('THIS IS JUST A UNIT TEST PAGE', None)
        self.assertTrue(wiki.get_page_version() == 1)
        ret = wiki.delete_page()
        self.assertTrue(ret == 204)
 
