from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if 'creds_harvesting' in self.event_json['tags']:
            for i in self.event_json['indicators']:
                if not 'attachment' in i['tags'] and not 'sandboxed_sample' in i['tags'] and (i['type'].startswith('Hash -') or i['type'] == 'Windows - FileName'):
                    self.logger.debug('Whitelisting "{}" creds harvesting indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
