import unittest

import subprocess

class CbInterfaceTestCase(unittest.TestCase):
    """ Tests for cbinterface. """

    def test_cbinterface_exists(self):
        """ Make sure the "cbinterface" command exists """

        try:
            subprocess.check_output('cbinterface --help', shell=True)
        except FileNotFoundError:
            self.fail('cbinterface does not exist in your path!')

    def test_md5_query(self):
        """ Make sure we can search for MD5 hashes """

        try:
            command = 'cbinterface query md5:c0ffeec0ffeec0ffeec0ffeec0ffeec0'
            output = subprocess.check_output(command, shell=True).decode('utf-8')
            if not '0 process segments returned by the query' in output:
                self.fail('Error with the MD5 query results')
        except:
            self.fail('Error running the MD5 query')
