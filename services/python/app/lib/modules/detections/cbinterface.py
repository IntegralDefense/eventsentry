import datetime
import dateutil.parser
import dateutil.tz
import logging
import pytz
import re
import subprocess

from lib.modules.DetectionModule import *
from cbinterface.modules.helpers import CONFIGURED_TIMEBASE as cbi_timezone

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # These are the companies that will get cbinterface queries.
        ignore_these_companies = self.config['ignore_these_companies']
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # These are the process names that will be ignored from the queries.
        ignore_these_process_names = self.config['ignore_these_process_names']
        ignore_these_process_names_string = ''
        for process_name in ignore_these_process_names:
            ignore_these_process_names_string += '-process_name:{} '.format(process_name)

        # These are the process MD5s that will be ignored from the queries.
        ignore_these_process_md5s = self.config['ignore_these_process_md5s']
        ignore_these_process_md5s_string = ''
        for process_md5 in ignore_these_process_md5s:
            ignore_these_process_md5s_string += '-process_md5:{} '.format(process_md5)

        # These are the computer names that will be ignored from the queries.
        ignore_these_computers = self.config['ignore_these_computers']
        ignore_these_computers_string = ''
        for computer in ignore_these_computers:
            ignore_these_computers_string += '-hostname:{} '.format(computer)

        # These are the users that will be ignored from the queries.
        ignore_these_users = self.config['ignore_these_users']
        ignore_these_users_string = ''
        for user in ignore_these_users:
            ignore_these_users_string += '-username:{} '.format(user)

        # Get all of the good Windows - FileName indicators from the event.
        good_indicators = [i for i in self.event_json['indicators'] if not i['whitelisted']]
        filenames = list(set([i['value'] for i in good_indicators if i['type'] == 'Windows - FileName' and (i['status'] == 'New' or i['status'] == 'Analyzed' or i['status'] == 'In Progress')]))
        self.logger.debug('cbinterface filenames: {}'.format(filenames))

        # Get all of the good Hash - MD5 indicators from the event.
        md5s = list(set([i['value'] for i in good_indicators if i['type'] == 'Hash - MD5' and (i['status'] == 'New' or i['status'] == 'Analyzed' or i['status'] == 'In Progress')]))
        self.logger.debug('cbinterface md5s: {}'.format(md5s))

        # Get the event time so that we can limit the scope of the cbinterface queries.
        event_time = None
        if self.event_json['emails']:
            event_time = self.event_json['emails'][0]['received_time']
        elif self.event_json['ace_alerts']:
            event_time = self.event_json['ace_alerts'][0]['time']

        # Continue if we have an event time.
        if event_time:

            # convert to whatever default timezone cbinterface is configured to use (default is GMT)
            event_time_obj = dateutil.parser.parse(event_time, ignoretz=False)
            now_aware = event_time_obj.replace(tzinfo=cbi_timezone)
            cbi_time_string = str(now_aware.astimezone(cbi_timezone))[0:10]
            cbi_time_string = '{} 00:00:00'.format(cbi_time_string)

            self.logger.debug('cbinterface cbi_time_string: {}'.format(cbi_time_string))

            # Run the cbinterface commands for each company in the event.
            for company in company_names:
            
                # Search for each filename.
                for filename in filenames:

                    # Build and run the cbinterface command.
                    command = 'cbinterface -e {} query --no-warnings \'{} {} {} {} (filemod:"{}" OR cmdline:"{}")\' -s \'{}\''.format(company, ignore_these_process_names_string, ignore_these_process_md5s_string, ignore_these_computers_string, ignore_these_users_string, filename, filename, cbi_time_string)
                    self.logger.debug(command)
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

                    command = 'cbinterface -e {} query --no-warnings \'{} {} {} {} md5:{}\' -s \'{}\''.format(company, ignore_these_process_names_string, ignore_these_process_md5s_string, ignore_these_computers_string, ignore_these_users_string, md5, cbi_time_string)
                    self.logger.debug(command)
                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the search returned something.
                        if output:

                            # Loop over each of the lines to try and find the GUI Link line.
                            for line in output.splitlines():

                                if 'GUI Link: ' in line:
                                    gui_link = line.replace('GUI Link: ', '').strip()
                                    self.detections.append('! DETECTED MD5 {} ! {}'.format(md5, gui_link))
                                    self.tags.append('incidents')
                                    self.tags.append('exploitation')
                                    self.extra.append(output)
                    except:
                        self.logger.exception('Error running cbinterface command: {}'.format(command))
