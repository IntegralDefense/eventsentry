import configparser
import logging
import os
import time

from lib.modules.BaseModule import *

class DetectionModule(BaseModule):
    def __init__(self, name='', event_json={}):

        super().__init__(family='detections', name=name, event_json=event_json)

        self.tags = []
        self.detections = []
        self.extra = []

