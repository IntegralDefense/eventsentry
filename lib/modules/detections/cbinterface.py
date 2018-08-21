import datetime
import logging
import re
import subprocess

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # These are the companies that will get cbinterface queries.
        ignore_these_companies = list(set(self.config.get('production', 'ignore_these_companies').split(',')))
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # Get all of the good Windows - FileName indicators from the event.
        good_indicators = [i for i in self.event_json['indicators'] if not i['whitelisted']]
        filenames = list(set([i['value'] for i in good_indicators if i['type'] == 'Windows - FileName' and (i['status'] == 'New' or i['status'] == 'Analyzed')]))

        # Get all of the good Hash - MD5 indicators from the event.
        md5s = list(set([i['value'] for i in good_indicators if i['type'] == 'Hash - MD5' and (i['status'] == 'New' or i['status'] == 'Analyzed')]))

        # Run the cbinterface commands for each company in the event.
        for company in company_names:
        
            # Search for each filename.
            for filename in filenames:

                # Build and run the cbinterface command.
                command = 'cbinterface -e {} query filemod:"{}"'.format(company, filename)
                try:
                    output = subprocess.check_output(command, shell=True).decode('utf-8')

                    # If there was output, it means the search returned something.
                    if output:

                        # Loop over each of the lines to try and find the GUI Link line.
                        for line in output.splitlines():

                            if 'GUI Link: ' in line:
                                gui_link = line.replace('GUI Link: ', '').strip()
                                self.detections.append('! DETECTED FILENAME {} ! {}'.format(filename, gui_link))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                self.extra.append(output)
                except:
                    self.logger.exception('Error running cbinterface command: {}'.format(command))

            # Search for each MD5.
            for md5 in md5s:

                command = 'cbinterface -e {} query md5:{}'.format(company, md5)
                try:
                    output = subprocess.check_output(command, shell=True).decode('utf-8')

                    # If there was output, it means the search returned something.
                    if output:

                        # Loop over each of the lines to try and find the GUI Link line.
                        for line in output.splitlines():

                            if 'GUI Link: ' in line:
                                gui_link = line.replace('GUI Link: ', '').strip()
                                self.detections.append('! DETECTED MD5 {} ! {}'.format(filename, gui_link))
                                self.tags.append('incidents')
                                self.tags.append('exploitation')
                                self.extra.append(output)
                except:
                    self.logger.exception('Error running cbinterface command: {}'.format(command))
