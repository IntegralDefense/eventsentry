from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        for alert in self.event_json['ace_alerts']:
            if 'Phish Spoof ' in alert['description'] and ' Exec ' in alert['description']:
                self.detections.append('Detected an exec spoof phish: {}'.format(alert['description']))
                self.tags.append('bec')
                self.tags.append('exec_spoof')

