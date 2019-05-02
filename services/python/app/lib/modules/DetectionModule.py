from lib.modules.BaseModule import *
import logging

class DetectionModule(BaseModule):
    def __init__(self, name='', event_json={}):

        super().__init__(family='detections', name=name, event_json=event_json)

        self.tags = []
        self.detections = []
        self.old_detections = event_json['detections']
        self.extra = []
        self.old_extra = event_json['detections_extra']

