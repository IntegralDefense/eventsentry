from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        for i in self.event_json['indicators']:
            if i['type'] == 'URI - Domain Name' and i['value'].endswith('.arpa'):
                self.logger.debug('Whitelisting "{}" .arpa indicator: {}'.format(i['type'], i['value']))
                i['whitelisted'] = True
