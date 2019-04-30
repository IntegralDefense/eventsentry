from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if 'emotet' in self.event_json['tags']:
            for i in self.event_json['indicators']:
                if i['type'] == 'URI - Path' or i['type'] == 'Email - Subject' or 'from_address' in i['tags'] or 'from_domain' in i['tags'] or i['type'] == 'Address - ipv4-addr' or i['type'] == 'Windows - FileName' or 'dropped_file' in i['tags']:
                    self.logger.debug('Whitelisting "{}" Emotet indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
