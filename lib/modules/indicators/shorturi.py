from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        for i in self.event_json['indicators']:
            # Remove any URI path indicators if the path is what we consider to be too short. Skip any manual indicators.
            if i['type'] == 'URI - Path' and len(i['value']) < 12 and not 'manual_indicator' in i['tags']:
                self.logger.debug('Whitelisting URI path indicator due to length: {}'.format(i['value']))
                i['whitelisted'] = True
