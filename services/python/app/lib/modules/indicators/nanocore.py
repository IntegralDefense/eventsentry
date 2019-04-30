from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if 'nanocore' in self.event_json['tags']:
            for i in self.event_json['indicators']:
                if i['type'] == 'Windows - FileName' and not 'sandboxed_sample' in i['tags']:
                    self.logger.debug('Whitelisting "{}" Nanocore indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
