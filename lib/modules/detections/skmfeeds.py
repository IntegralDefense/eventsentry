from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each e-mail in the event.
        for email in self.event_json['emails']:

            if 'skmfeeds' in email['headers'].lower():
                self.detections.append('Detected an skmfeeds e-mail by the headers: {}'.format(email['path']))
                self.tags.append('skmfeeds')

