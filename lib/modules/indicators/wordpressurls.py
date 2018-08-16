from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        for i in self.event_json['indicators']:
            if i['type'] == 'URI - URL' or i['type'] == 'URI - Path':
                
                # Make sure this is a Wordpress URL or path with .js in it.
                if ('wp-content' in i['value'] or 'wp-includes' in i['value']) and '.js' in i['value']:
                    self.logger.debug('Whitelisting Wordpress .js indicator: {}'.format(i['value']))
                    i['whitelisted'] = True
