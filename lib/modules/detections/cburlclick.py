from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        for alert in self.event_json['ace_alerts']:
            if 'CB URL Click' in alert['description']:
                self.detections.append('Detected a CB URL clicker: {}'.format(alert['description']))
                self.tags.append('incidents')
                self.tags.append('exploitation')

