import unittest

from lib.constants import PROXYCHAINS, PROXYCHAINS_CONFIG
import os
import subprocess

class ProxychainsTestCase(unittest.TestCase):
    """ Tests for proxychains. """

    def test_proxychains(self):
        try:
            os.environ['http_proxy'] = ''
            os.environ['https_proxy'] = ''
            download_path = '/tmp/google_proxychains_test.html'
            url = 'https://www.google.com'
            command = '{} -f {} wget -O {} -T {} "{}"'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, download_path, 10, url)
            subprocess.call(command, shell=True)
            success = os.path.exists(download_path)
            try:
                os.remove(download_path)
            except:
                pass
            self.assertTrue(success)
        except:
            self.fail('Error when calling proxychains')
