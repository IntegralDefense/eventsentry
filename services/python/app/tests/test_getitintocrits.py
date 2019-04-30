import unittest

from lib.constants import GETITINTOCRITS, BUILD_RELATIONSHIPS
import os
import subprocess

class GetitintocritsTestCase(unittest.TestCase):
    """ Tests for getitintocrits. """

    def test_getitintocrits_exists(self):
        """ Make sure the "getitintocrits.py" command exists """

        self.assertTrue(os.path.exists(GETITINTOCRITS))

    def test_build_relationships_exists(self):
        """ Make sure the "build_relationships.py" command exists """

        self.assertTrue(os.path.exists(BUILD_RELATIONSHIPS))

    def test_getitintocrits_config(self):
        """ Perform a dry run of getitintocrits.py """

        try:
            output = subprocess.check_output('{} -s OSINT -r asdf'.format(GETITINTOCRITS), shell=True).decode('utf-8')
            if not 'left_id,left_type,right_id,right_type,rel_type,rel_date,rel_confidence,rel_reason' in output:
                self.fail('Unexpected output from getitintocrits.py: {}'.format(output))
            if not os.path.exists('relationships.txt'):
                self.fail('Did not generate relationships.txt: {}'.format(output))
            try:
                os.remove('relationships.txt')
            except:
                pass
        except:
            self.fail('Error running getitintocrits.py')
