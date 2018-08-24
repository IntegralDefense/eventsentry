import unittest

from lib.constants import GETITINTOCRITS, BUILD_RELATIONSHIPS
import os
import subprocess

class GetitintocritsTestCase(unittest.TestCase):
    """ Tests for getitintocrits. """

    def test_getitintocrits_exists(self):
        if not os.path.exists(GETITINTOCRITS):
            self.fail('Error locating getitintocrits.py: {}'.format(GETITINTOCRITS))

        if not os.path.exists(BUILD_RELATIONSHIPS):
            self.fail('Error locating build_relationships.py: {}'.format(BUILD_RELATIONSHIPS))

    def test_getitintocrits_config(self):
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
