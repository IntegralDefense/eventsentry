import configparser
import logging
import os
import time
from abc import ABC, abstractmethod

from lib.config import config

class BaseModule(ABC):
    def __init__(self, family='', name='', event_json={}):
        """ Initialize the module """

        self.family = family
        self.name = name
        self.event_json = event_json
        self.logger = logging.getLogger()
        self.runtime = 0
        self.config = config['modules'][family][self.name]

    @abstractmethod
    def run(self):
        """ Executes the module """

        pass

    def timed_run(self):
        """ Executes the module and logs the elapsed time """

        if self.config['enabled']:
            start = time.time()
            self.run()
            end = time.time()
            self.runtime = end - start
