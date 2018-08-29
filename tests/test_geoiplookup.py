import unittest

import subprocess

class GeoiplookupTestCase(unittest.TestCase):
    """ Tests for geoiplookup. """

    def test_geoiplookup(self):
        """ Make sure the "geoiplookup" command exists and functions properly """

        try:
            output = subprocess.check_output('geoiplookup 1.1.1.1', shell=True).decode('utf-8')
            if not 'Cloudflare' in output:
                self.fail('Are your geoip databases in /usr/share/GeoIP/ ???')
        except:
            self.fail('Error when calling geoiplookup')
