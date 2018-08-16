from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if '1000_talents' in self.event_json['tags'] or '1000 talents' in self.event_json['tags'] or any('1000 talents' in a['tags'] for a in self.event_json['ace_alerts']) or any('1000_talents' in a['tags'] for a in self.event_json['ace_alerts']):
            for i in self.event_json['indicators']:
                if i['type'].startswith('URI -'):
                    self.logger.debug('Whitelisting "{}" 1000 Talents indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
