import datetime
import json
import logging
import re
import subprocess

from lib.ace import Alert, AlertSubmitException
from lib.constants import SPLUNKLIB
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # These are the companies that will get Splunk queries.
        ignore_these_companies = self.config['ignore_these_companies']
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # These are the domains to ignore when searching for missed phish by the sender address.
        ignore_these_domains = self.config['ignore_these_domains']

        # Get the start time.
        try:
            received_time = datetime.datetime.strptime(self.event_json['emails'][-1]['received_time'][0:19], '%Y-%m-%d %H:%M:%S')
            received_time = received_time.replace(hour=0, minute=0, second=0, microsecond=0)
            end_time = received_time.replace(hour=23, minute=59, second=59, microsecond=0)
            start_time = received_time.strftime('%Y-%m-%d %H:%M:%S')
        except:
            self.logger.exception('Error making start time and end time.')
            start_time = None

        # Get all of the existing message-ids in the event.
        existing_message_ids = [email['message_id'] for email in self.event_json['emails']]

        # Get all of the unique senders that aren't Informational or whitelisted by sender domain.
        senders = set([i['value'] for i in self.event_json['indicators'] if not i['whitelisted'] and 'from_address' in i['tags'] and (i['status'] == 'New' or i['status'] == 'Analyzed' or i['status'] == 'In Progress')])
        senders = [sender for sender in senders if not any(ignore_domain in sender for ignore_domain in ignore_these_domains)]

        # Get all of the unique attachment hashes that aren't whitelisted by sender domain.
        attachment_hashes = set()
        for email in self.event_json['emails']:
            if not any(ignore_domain in email['from_address'] for ignore_domain in ignore_these_domains):
                for attach in email['attachments']:
                    if attach['sha256'] and attach['size']:
                        attachment_hashes.add(attach['sha256'])

        # Get all of the unique sender (do not care about whitelisted) and subject pairs.
        sender_subjects = set()
        for email in self.event_json['emails']:
            sender_subjects.add((email['from_address'], email['subject']))

        # Only continue if we have a valid start and end time.
        if start_time and end_time:

            # Run the Splunk search for each company we found in the alerts.
            for company in company_names:

                # Store the missed phish that we find.
                missed_phish = set()

                """
                QUERY SPLUNK FOR MISSED PHISH BY SENDER (DON'T CARE ABOUT WHITELISTED) AND SUBJECT PAIRS
                """

                for sender_subject in sender_subjects:
                    sender = sender_subject[0]
                    subject = sender_subject[1]

                    # Store the Splunk output lines.
                    output_lines = []

                    # This is the actual command line version of the Splunk query.
                    command = '{} --enviro {} -s "{}" -e "{}" --json "index=email* mail_from=\\"*{}*\\" subject=\\"*{}*\\"| table message_id subject"'.format(SPLUNKLIB, company, start_time, end_time, sender, subject)
                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:
                            output_json = json.loads(output)
                            for result in output_json['result']:
                                if not result['message_id'] in existing_message_ids:
                                    missed_phish.add((result['message_id'], result['subject']))
                    except:
                        self.logger.exception('Error when running Splunk search: {}'.format(command))

                """
                QUERY SPLUNK FOR MISSED PHISH BY SENDER
                """

                for sender in senders:

                    # Store the Splunk output lines.
                    output_lines = []

                    # This is the actual command line version of the Splunk query.
                    command = '{} --enviro {} -s "{}" -e "{}" --json "index=email* mail_from=\\"*{}*\\" | table message_id subject"'.format(SPLUNKLIB, company, start_time, end_time, sender)
                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:
                            output_json = json.loads(output)
                            for result in output_json['result']:
                                if not result['message_id'] in existing_message_ids:
                                    missed_phish.add((result['message_id'], result['subject']))
                    except:
                        self.logger.exception('Error when running Splunk search: {}'.format(command))

                """
                QUERY SPLUNK FOR MISSED PHISH BY ATTACHMENT HASH
                """

                for attachment_hash in attachment_hashes:

                    # Store the Splunk output lines.
                    output_lines = []

                    # This is the actual command line version of the Splunk query.
                    command = '{} --enviro {} -s "{}" -e "{}" --json "index=email* attachment_hashes=\\"*{}*\\" | table message_id subject"'.format(SPLUNKLIB, company, start_time, end_time, attachment_hash)
                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:
                            output_json = json.loads(output)
                            for result in output_json['result']:
                                if not result['message_id'] in existing_message_ids:
                                    missed_phish.add((result['message_id'], result['subject']))

                    except:
                        self.logger.exception('Error when running Splunk search: {}'.format(command))

                # Create new ACE alerts for each potentially missed phish.
                file_paths = [f['path'] for f in self.event_json['files']]
                for phish in missed_phish:

                    # Make sure there isn't already an email in the event that matches this message-id.
                    # This can happen if the phish is an embedded/attached email and we are alerting on the
                    # "parent" email's message-id as being a missed phish.
                    message_id = phish[0]
                    subject = phish[1]
                    if not any(message_id in path for path in file_paths):

                        self.logger.warning('Creating alert for potentially missed phish: {}'.format(message_id))
                        
                        alert = Alert(
                            tool = 'Event Sentry',
                            tool_instance = self.config['ace_tool_instance'],
                            alert_type = 'eventsentry',
                            desc = 'Event Sentry - Possible Missed Phish: {}'.format(subject),
                            event_time = datetime.datetime.now(),
                            details = {'event_name': self.event_json['name'], 'wiki_url': self.event_json['wiki_url']})
                        alert.add_observable('message_id', message_id)

                        self.detections.append('! DETECTED POSSIBLE MISSED PHISH: {} <--- CHECK ACE FOR THE ALERT'.format(message_id))
                        
                        # Submit the alert to the proper ACE system (based on the company).
                        try:
                            ace_submit = self.config['ace_instances'][company.lower()]['ace_submit']
                            alert.submit(ace_submit, 'eventsentry')
                        except:
                            self.logger.exception('Error submitting missed phish alert to ACE.')
