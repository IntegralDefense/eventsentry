from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        for alert in self.event_json['ace_alerts']:
            if 'user_reported' in alert['tags']:
                self.detections.append('Detected a user-reported phish: {}'.format(alert['url']))
                self.tags.append('phishme')

