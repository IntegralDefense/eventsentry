from lib.modules.IndicatorModule import *

class Module(IndicatorModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} indicator module'.format(self.name))

        if 'mitmb' in self.event_json['tags']:

            # Find the "from_domain" indicator.
            from_domain = ''
            for i in self.event_json['indicators']:
                if i['type'] == 'URI - Domain Name' and 'from_domain' in i['tags']:
                    from_domain = i['value']

            # Check if the from_domain indicator is found inside any of the other domain indicators.
            if from_domain:
                for i in self.event_json['indicators']:
                    if i['type'] == 'URI - Domain Name' and not from_domain == i['value'] and from_domain in i['value']:
                        self.logger.debug('Whitelisting MITMB indicator based on the from_domain {}: {}'.format(from_domain, i['value']))

                        # Whitelist any relationships as well.
                        for r in i['relationships']:
                            for ind in self.event_json['indicators']:
                                if ind['value'] == r:
                                    self.logger.debug('Whitelisting MITMB indicator based on relationship to domain: {}'.format(r))
                                    ind['whitelisted'] = True
