from lib.modules.BaseModule import *

class IndicatorModule(BaseModule):
    def __init__(self, name='', event_json={}):

        super().__init__(family='indicators', name=name, event_json=event_json)
