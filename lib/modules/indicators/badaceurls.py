from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        for i in self.event_json['indicators']:
            # Remove any URL and URI path indicators if they are bad URLs from ACE with double quotes.
            if (i['type'] == 'URI - URL' or i['type'] == 'URI - Path') and (i['value'].count('"') == 2 or i['value'].count("'") == 2):
                self.logger.debug('Whitelisting URL indicator due to ACE double quote bug: {}'.format(i['value']))
                i['whitelisted'] = True
