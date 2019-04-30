from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if 'ransomware' in self.event_json['tags']:
            for i in self.event_json['indicators']:
                if not 'attachment' in i['tags'] and not 'sandboxed_sample' in i['tags']:
                    if i['type'].startswith('Hash -') or i['type'] == 'Windows - FileName':
                        self.logger.debug('Whitelisting "{}" ransomware indicator: {}'.format(i['type'], i['value']))
                        i['whitelisted'] = True
