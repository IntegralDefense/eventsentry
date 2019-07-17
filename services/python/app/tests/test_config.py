import configparser
import os
import subprocess
import sys
import unittest

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

        self.assertTrue(os.path.exists(config.get('production', 'docker_event_path_prefix')))

    def test_event_directory_permissions(self):
        """ Make sure the parent event directory is writable """

        self.assertTrue(os.access(config.get('production', 'docker_event_path_prefix'), os.W_OK))

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
 
