import configparser
import logging
import os
import time
from abc import ABC, abstractmethod

class BaseModule(ABC):
    def __init__(self, family='', name='', event_json={}):
        """ Initialize the module """

        self.family = family
        self.name = name
        self.event_json = event_json

        # Start logging and load the module's config file if it exists.
        self.logger = logging.getLogger()
        this_dir = os.path.join(os.path.dirname(__file__))
        config_path = os.path.join(this_dir, self.family, 'etc', 'local', '{}.ini'.format(self.name))
        if os.path.exists(config_path):
            self.config = configparser.RawConfigParser()
            self.config.read(config_path)
        else:
            self.config = None

        self.runtime = 0

    @abstractmethod
    def run(self):
        """ Executes the module """

        pass

    def timed_run(self):
        """ Executes the module and logs the elapsed time """

        start = time.time()
        self.run()
        end = time.time()
        self.runtime = end - start
