import ipaddress
import os
import subprocess
import tempfile
import unittest

from lib.constants import PROXYCHAINS, PROXYCHAINS_CONFIG

class ProxychainsTestCase(unittest.TestCase):
    """ Tests for proxychains. """

    def test_proxychains(self):
        """ Make sure proxychains can actually download something """

        try:
            os.environ['http_proxy'] = ''
            os.environ['https_proxy'] = ''

            temp = tempfile.NamedTemporaryFile()
            url = 'https://wtfismyip.com/text'
            command = '{} -f {} wget -O {} -T {} "{}"'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, temp.name, 10, url)
            subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

            with open(temp.name) as f:
                self.assertTrue(ipaddress.ip_address(f.read().strip()))

            temp.close()

        except:
            self.fail('Error when calling proxychains')
