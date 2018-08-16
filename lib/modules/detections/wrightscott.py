from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each e-mail address in the event.
        for email_address in [i['value'] for i in self.event_json['indicators'] if i['type'] == 'Email - Address']:

            if 'wrightscott' in email_address.lower():
                self.detections.append('Detected a Wright Scott e-mail address: {}'.format(email_address))
                self.tags.append('wrightscott')

