import unittest

from lib.constants import SPLUNKLIB
import configparser
import os
import subprocess

class SplunklibTestCase(unittest.TestCase):
    """ Tests for splunklib. """

    def test_splunklib_exists(self):
        try:
            subprocess.check_output('{} --help'.format(SPLUNKLIB), shell=True)
        except:
            self.fail('Error when calling splunk.py')

    def test_splunklib_config_exists(self):
        home = os.path.expanduser('~')
        config_path = os.path.join(home, '.splunklib.ini')
        if not os.path.exists(config_path):
            self.fail('splunklib config does not exist: {}'.format(config_path))

    def test_splunklib_environments(self):
        home = os.path.expanduser('~')
        config_path = os.path.join(home, '.splunklib.ini')
        config = configparser.ConfigParser()
        config.read(config_path)
        for environment in config.sections():
            command = '{} --enviro {} "index=* | head 1"'.format(SPLUNKLIB, environment)
            try:
                output = subprocess.check_output(command, shell=True).decode('utf-8')
            except:
                self.fail('Error running splunklib command: {}'.format(command))
