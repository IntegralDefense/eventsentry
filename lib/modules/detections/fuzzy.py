import subprocess

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Try to detect Fuzzy by a Nigerian hunt ACE alert.
        for ace_alert in self.event_json['ace_alerts']:
            if 'Email Nigeria Originating' in ace_alert['description']:
                self.detections.append('Detected Nigerian (Fuzzy) by ACE alert: {}'.format(ace_alert['description']))
                self.tags.append('campaign')
                self.tags.append('fuzzy')

        # Try to detect Fuzzy by the IP geolocation.
        for ip in set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'Address - ipv4-addr' and not i['whitelisted']]):

            # Perform the geoiplookup command.
            try:
                output = subprocess.check_output(['geoiplookup', ip]).decode('utf-8')
                if 'nigeria' in output.lower():
                    self.detections.append('Detected Nigerian (Fuzzy) IP address by geolocation: {}'.format(ip))
                    self.tags.append('campaign')
                    self.tags.append('fuzzy')
            except:
                self.logger.exception('Could not geolocate IP address: {}'.format(ip))

        """
        # Try to detect Fuzzy by WHOIS information.
        for whois in event_json['whois']:
            if 'country: ng' in whois['raw'].lower() or 'country: nigeria' in whois['raw'].lower():
                extra.append(whois['raw'])
                detections.append('Detected Nigerian (Fuzzy) domain by WHOIS: {}'.format(whois['domain']))
                tags.append('campaign')
                tags.append('fuzzy')
        """
