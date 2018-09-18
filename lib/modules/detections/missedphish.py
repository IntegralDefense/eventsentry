import datetime
import json
import logging
import re
import subprocess

from lib.ace_client_lib.ace_client_lib.client import Alert
from lib.constants import SPLUNKLIB
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # These are the companies that will get Splunk queries.
        ignore_these_companies = list(set(self.config.get('production', 'ignore_these_companies').split(',')))
        company_names = set()
        for alert in self.event_json['ace_alerts']:
            if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
                company_names.add(alert['company_name'])

        # Get the start time.
        try:
            received_time = datetime.datetime.strptime(self.event_json['emails'][0]['received_time'][0:19], '%Y-%m-%d %H:%M:%S')
            delta = datetime.timedelta(hours=1)
            start_time = (received_time - delta).strftime('%Y-%m-%d %H:%M:%S')
            end_time = (received_time + delta).strftime('%Y-%m-%d %H:%M:%S')
        except:
            self.logger.exception('Error making start and end time.')
            start_time = None
            end_time = None

        # Get all of the existing message-ids in the event.
        existing_message_ids = [email['message_id'] for email in self.event_json['emails']]

        # Get all of the unique sender+subject pairs, sender+attachment name pairs, and attachment SHA256 hashes.
        sender_subject_pairs = set()
        sender_attachment_pairs = set()
        attachment_hashes = set()
        for email in self.event_json['emails']:
            if email['from_address'] and email['subject']:
                sender_subject_pairs.add((email['from_address'], email['subject']))
            for attach in email['attachments']:
                attachment_hashes.add(attach['sha256'])
                if email['from_address'] and attach['name']:
                    sender_attachment_pairs.add((email['from_address'], attach['name']))

        # Only continue if we have a valid start and end time.
        if start_time and end_time:

            # Run the Splunk search for each company we found in the alerts.
            for company in company_names:

                # Store the missed phish that we find.
                missed_phish = set()

                """
                QUERY SPLUNK FOR MISSED PHISH BY SENDER+SUBJECT
                """

                for sender_subject_pair in sender_subject_pairs:

                    # Store the Splunk output lines.
                    output_lines = []

                    # This is the actual command line version of the Splunk query.
                    sender = sender_subject_pair[0]
                    subject = sender_subject_pair[1]
                    command = '{} --enviro {} -s "{}" --json "index=email* subject=\\"{}\\" AND mail_from=\\"*{}*\\" | table message_id subject"'.format(SPLUNKLIB, company, start_time, subject, sender) 
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
                QUERY SPLUNK FOR MISSED PHISH BY SENDER+ATTACHMENT NAME
                """

                for sender_attachment_pair in sender_attachment_pairs:

                    # Store the Splunk output lines.
                    output_lines = []

                    # This is the actual command line version of the Splunk query.
                    sender = sender_attachment_pair[0]
                    attachment_name = sender_attachment_pair[1]
                    command = '{} --enviro {} -s "{}" --json "index=email* attachment_names=\\"*{}*\\" AND mail_from=\\"*{}*\\" | table message_id subject"'.format(SPLUNKLIB, company, start_time, attachment_name, sender)
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
                    command = '{} --enviro {} -s "{}" "index=email* attachment_hashes=\\"*{}*\\" | table message_id subject"'.format(SPLUNKLIB, company, start_time, attachment_hash)
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
                for phish in missed_phish:
                    message_id = phish[0]
                    subject = phish[1]
                    self.logger.warning('Creating alert for potentially missed phish: {}'.format(message_id))
                    
                    alert = Alert(
                        tool = 'Event Sentry',
                        tool_instance = self.config.get(company, 'ace_tool_instance'),
                        alert_type = 'eventsentry',
                        desc = 'Event Sentry - Possible Missed Phish: {}'.format(subject),
                        event_time = datetime.datetime.now(),
                        details = '')
                    alert.add_observable('message_id', message_id)

                    self.detections.append('! DETECTED POSSIBLE MISSED PHISH: {} <--- CHECK ACE FOR THE ALERT'.format(message_id))
                    
                    # Submit the alert to the proper ACE system (based on the company).
                    try:
                        ace_submit = self.config.get(company, 'ace_submit')
                        alert.submit(ace_submit, 'eventsentry')
                    except:
                        self.logger.exception('Error submitting missed phish alert to ACE.')
