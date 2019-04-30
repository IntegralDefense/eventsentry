from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        url_shorteners = self.config['domains']
        url_shorteners = [u.lower() for u in url_shorteners]

        for i in self.event_json['indicators']:
            # Remove any URI path indicators if one of its relationships is a URL shortener service.
            if i['type'] == 'URI - Path' and any(r.lower() in url_shorteners for r in i['relationships']):
                self.logger.debug('Whitelisting URI path indicator due to URL shortener relationship: {}'.format(i['value']))
                i['whitelisted'] = True
