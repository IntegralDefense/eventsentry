#!/usr/bin/env python3

import os
import unittest
import sys

parent_dir = os.path.join(os.path.dirname(__file__), '..')
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from tests import test_cbinterface
from tests import test_config
from tests import test_geoiplookup
from tests import test_proxychains
from tests import test_splunklib

if __name__ == '__main__':
    # Initialize the test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add tests to the test suite
    suite.addTests(loader.loadTestsFromModule(test_cbinterface))
    suite.addTests(loader.loadTestsFromModule(test_geoiplookup))
    suite.addTests(loader.loadTestsFromModule(test_proxychains))
    suite.addTests(loader.loadTestsFromModule(test_splunklib))
    suite.addTests(loader.loadTestsFromModule(test_config))

    # Initialize a runner, and pass it your suite to run
    runner = unittest.TextTestRunner(verbosity=3)
    result = runner.run(suite)
