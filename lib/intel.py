import configparser
import csv
import filecmp
import logging
import os
import subprocess

from lib.constants import HOME_DIR

class EventIntel:
    def __init__(self, event_json, indicator_summary_table):
        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # Start logging.
        self.logger = logging.getLogger()

        # Save the event JSON and Indicator Summary table.
        self.event_json = event_json
        self.indicator_summary_table = indicator_summary_table

    def build_symlink_directory_structure(self):
        """ This function creates the .crits intel directory and builds the email/sample symlink
            directory structure based on the e-mails and sandboxed samples in the event JSON. """

        # Make the path to where we're going to store the event intel.
        event_crits_root = os.path.join(self.event_json['path'], '.crits')
        
        # Make sure the .crits directory exists inside the event directory.
        if not os.path.exists(event_crits_root):
            self.logger.debug('Creating .crits intel directory.')
            os.makedirs(event_crits_root)
        # If it does exist, delete it and start fresh.
        else:
            try:
                rm_command = 'rm -rf ' + event_crits_root
                subprocess.check_call(rm_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                os.makedirs(event_crits_root)
                self.logger.debug('Deleting .crits intel directory and starting fresh.')
            except subprocess.CalledProcessError:
                self.logger.exception('Unable to delete .crits: {}'.format(event_crits_root))
                
        # Loop over any e-mails in the event.
        for email in self.event_json['emails']:

            # Make sure a symlink to this e-mail exists in the intel directory.
            email_symlink_dir = self.ensure_symlink_exists(email['path'], event_crits_root, 'email')

            # Inject the e-mail symlink directory path into the e-mail JSON.
            email['intel_path'] = email_symlink_dir

            # Loop over any attachments in this e-mail.
            for attachment in email['attachments']:

                # Continue if we know where this file is in the event directory and the e-mail symlink exists.
                if 'event_path' in attachment:

                    # Make sure a symlink to this attachment exists in the e-mail symlink directory.
                    attachment_symlink_dir = self.ensure_symlink_exists(attachment['event_path'], email_symlink_dir, 'sample')

        # Loop over any HTML files in the event (but exclude e-mail bodies).
        for html_path in [f['path'] for f in self.event_json['files'] if f['category'] == 'html' and not 'rfc822' in f['path']]:

            # Make sure a symlink to this HTML file exists in the intel directory.
            html_symlink_dir = self.ensure_symlink_exists(html_path, event_crits_root, 'sample')

        # The sandbox reports are a bit trickier to symlink since we need to figure out:
            # Whether or not this sample is associated with an e-mail somehow.
            # Whether or not the sample is a "root" sample (was not dropped by another sample)
            # All the places its parent sample (if it has a parent) was already symlinked.

        # In the worst case scenario, the order of the sandbox reports might require us to
        # loop over them the same number of times as there are number of sandbox reports so
        # that we can ensure each report's parent sample (if it has a parent) is already symlinked.
        for x in range(len(self.event_json['sandbox'])):

            # Loop over the the sandboxed samples.
            for sample in self.event_json['sandbox']:

                try:
                    # Loop over the samples to identify if the current sample has a parent sample.
                    root_sample = True
                    parent_sample = None
                    for possible_parent in self.event_json['sandbox']:

                        # If these are not the same samples, check if they are a parent/child pair.
                        if not sample['event_path'] == possible_parent['event_path']:

                            # We consider this to be a root sample if the MD5 and the filename do not appear within
                            # the dropped files of any of the other sandboxed samples.
                            if any(sample['md5'] == dropped['md5'] or sample['filename'] == dropped['filename'] for dropped in possible_parent['dropped_files']):
                                self.logger.debug('Matched parent sample "{}" with child sample "{}"'.format(possible_parent['filename'], sample['filename']))
                                root_sample = False
                                parent_sample = possible_parent

                    # If this is a root sample, we need to figure out if it is somehow associated with an e-mail
                    # or if the sample belongs at the event level.
                    if root_sample:

                        # Loop over the e-mails in the event to see if this sample is in the same directory.
                        email_sample = False
                        for email in self.event_json['emails']:

                            # If we found this sample somewhere in the same folder as this e-mail in
                            # the event directory, we need to symlink to the sample in the same directory
                            # as the e-mail inside the intel directory.
                            if self.find_event_sample(sample['md5'], email['path']):
                                email_sample = True

                                # Make sure the symlink to the sample exists in the e-mail directory.
                                sample_symlink_dir = self.ensure_symlink_exists(sample['event_path'], email['intel_path'], 'sample')

                                # Inject the sample's intel symlink path into the sandbox JSON.
                                sample['intel_path'] = sample_symlink_dir

                        # If this sample is not associated with an e-mail, make its symlink at the event level.
                        if not email_sample:

                            # Make sure the symlink to the sample exists in the event directory.
                            sample_symlink_dir = self.ensure_symlink_exists(sample['event_path'], event_crits_root, 'sample')

                            # Inject the sample's intel symlink path into the sandbox JSON.
                            sample['intel_path'] = sample_symlink_dir

                    # This is a dropped file.
                    else:

                        # Find all the paths where the parent sample has already been symlinked.
                        parent_symlink_paths = self.find_all_symlinked_paths(parent_sample['event_path'], event_crits_root)

                        for parent_symlink_path in parent_symlink_paths:

                            # Make sure the symlink to the child sample exists in the parent sample directory.
                            sample_symlink_dir = self.ensure_symlink_exists(sample['event_path'], parent_symlink_path, 'sample')

                            # Inject the sample's intel symlink path into the sandbox JSON.
                            sample['intel_path'] = sample_symlink_dir

                    # Now we need to make sure symlinks exist for all of the sample's dropped files.
                    sample_symlink_paths = self.find_all_symlinked_paths(sample['event_path'], event_crits_root)
                    for sample_symlink_path in sample_symlink_paths:

                        # Loop over the sample's dropped files.
                        for dropped_file in sample['dropped_files']:

                            # Only symlink to this dropped file if it is not whitelisted.
                            if not dropped_file['status'] == 'Whitelisted':

                                # Continue if we know where this dropped file exists in the event directory.
                                if 'event_path' in dropped_file:

                                    # Make sure the symlink to the dropped file exists in the sample's intel directory.
                                    dropped_symlink_dir = self.ensure_symlink_exists(dropped_file['event_path'], sample_symlink_path, 'sample')
                            else:
                                try:
                                    self.logger.debug('Skipping whitelisted dropped file: {}'.format(dropped_file['event_path']))
                                except:
                                    self.logger.debug('Skipping whitelisted dropped file')

                except:
                    self.logger.exception('Unable to symlink sandbox sample: {}'.format(sample['filename']))

    def place_indicator_and_relationship_csvs(self):
        """ This function matches the good indicators in the Indicator Summary table in their
            appropriate indicators.csv locations inside the intel directory structure. """

        # Make the path to where we're going to store the event intel.
        event_crits_root = os.path.join(self.event_json['path'], '.crits')

        # Loop over each e-mail in the event.
        for email in self.event_json['emails']:

            # Figure out where this e-mail is symlinked.
            email_symlink_paths = self.find_all_symlinked_paths(email['path'], event_crits_root)

            # Find the indicators for each e-mail and write the indicators.csv file.
            for email_symlink_path in email_symlink_paths:
                indicators = self.find_indicators(email['path'])
                self.write_indicators_csv(email_symlink_path, indicators)
                self.write_relationships_csv(email_symlink_path, indicators)

        # Loop over each HTML file in the event (excluding e-mail bodies).
        for html_path in [f['path'] for f in self.event_json['files'] if f['category'] == 'html' and not 'rfc822' in f['path']]:

            # Figure out where this file is symlinked.
            html_symlink_paths = self.find_all_symlinked_paths(html_path, event_crits_root)

            # Find all the indicators for each HTML file and write the indicators.csv file.
            for html_symlink_path in html_symlink_paths:
                indicators = self.find_indicators(html_path)
                self.write_indicators_csv(html_symlink_path, indicators)
                self.write_relationships_csv(html_symlink_path, indicators)

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Figure out where this sample is symlinked.
            sample_symlink_paths = self.find_all_symlinked_paths(sample['event_path'], event_crits_root)

            if sample_symlink_paths:
                # We only want to write the sample's indicators once to speed up the upload to CRITS process.
                indicators = self.find_indicators(sample['event_path'])
                self.write_indicators_csv(sample_symlink_paths[0], indicators)
                self.write_relationships_csv(sample_symlink_paths[0], indicators)

        # Write any event-level indicators.
        indicators = self.find_indicators('')
        self.write_indicators_csv(event_crits_root, indicators)
        self.write_relationships_csv(event_crits_root, indicators)

    def write_indicators_csv(self, path, indicators):
        """ This function writes the supplied indicators in the indicators.csv file located at 'path'. """

        if indicators:
            # Make sure we have the directory that will hold the indicators.csv file.
            if os.path.isfile(path):
                path = os.path.dirname(path)

            # Build the indicators.csv path.
            csv_path = os.path.join(path, 'indicators.csv')

            # This is the header row for the indicators.csv file.
            indicator_csv_header = ['Indicator', 'Type', 'Threat Type', 'Attack Type', 'Description', 'Campaign',
                                    'Campaign Confidence', 'Confidence', 'Impact', 'Bucket List', 'Ticket', 'Action']

            # Check if the event has a campaign assigned to it.
            try:
                campaign = self.event_json['campaign']['crits']
                campaign_conf = 'low'
            except:
                campaign = ''
                campaign_conf = ''

            # Begin building the indicators.csv file.
            self.logger.debug('Writing indicators: {}'.format(csv_path))
            with open(csv_path, 'w', newline='') as c:
                csv_writer = csv.writer(c)
                csv_writer.writerow(indicator_csv_header)

                # Keep track of lines already written to avoid duplicates.
                written_lines = []

                # Loop over each indicator.
                for i in indicators:

                    # If the indicator is Informational, set the Confidence and Impact to "benign".
                    if i['status'] == 'Informational':
                        conf = 'benign'
                        impact = 'benign'
                    else:
                        conf = 'low'
                        impact = 'low'

                    # Create the bucket list string from the indicator + event tags.
                    # Remove any tags we want to ignore from the event tags.
                    tags = sorted(list(set(i['tags'] + self.event_json['tags'])))
                    ignore_these_labels = self.config.get('production', 'ignore_these_labels').split(',')
                    for label in ignore_these_labels:
                        try:
                            tags.remove(label)
                        except:
                            pass
                    bucket_list = ','.join(tags)

                    # Write the indicator line if we didn't already.
                    line = [i['value'], i['type'], '', '', '', campaign, campaign_conf, conf, impact, bucket_list, '', '']
                    if not line in written_lines:
                        csv_writer.writerow(line)
                        written_lines.append(line)

    def write_relationships_csv(self, path, indicators):
        """ This function writes the unique relationships into the .relationships file. """

        if indicators:
            # Make sure we have the directory that will hold the indicators.csv file.
            if os.path.isfile(path):
                path = os.path.dirname(path)

            # Build the indicators.csv path.
            csv_path = os.path.join(path, '.relationships')

            unique_relationships = []

            # Loop over each indicator we were given.
            for i in indicators:

                # Loop over each relationship in the indicator.
                for r in i['relationships']:

                    # Build a tuple of the relationship.
                    rel = (i['value'], r)

                    # Build a reversed tuple of the relationship.
                    reversed_rel = (r, i['value'])

                    # If neither form of the relationship are already in the list, add it.
                    if not rel in unique_relationships and not reversed_rel in unique_relationships:
                        unique_relationships.append(rel)

            # Begin building the .relationships file.
            if unique_relationships:
                self.logger.debug('Writing relationships: {}'.format(csv_path))
                with open(csv_path, 'w', newline='') as c:
                    csv_writer = csv.writer(c)

                    # Loop over each relationship.
                    for r in unique_relationships:

                        # Write the relationship line.
                        line = [r[0], r[1]]
                        csv_writer.writerow(line)

    def find_event_sample(self, md5, parent_dir):
        """ This function searches the parent directory in the event directory for a
            file that matches the given MD5 hash. If a match is found, it returns the path. """

        if os.path.isfile(parent_dir):
            parent_dir = os.path.dirname(parent_dir)
        for f in self.event_json['files']:
            if f['md5'] == md5 and parent_dir in f['path']:
                return f['path']

        return None

    def find_all_symlinked_paths(self, original_file_path, parent_dir):
        """ This function searches the parent directory for all of the paths that are symlinks
            pointing to the specified original file path. """

        paths = []

        for root, dirs, files in os.walk(parent_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.islink(file_path):
                    if os.path.realpath(file_path) == original_file_path:
                        paths.append(file_path)

        return paths

    def get_next_symlink_dir_name(self, symlink_parent_dir, symlink_dir_prefix):
        """ This function gets the next available directory number in the parent directory. """

        # Get a listing of the parent directory.
        dir_listing = os.listdir(symlink_parent_dir)

        # Only consider things that begin with the symlink_dir_prefix.
        prefix_dir_listing = [item for item in dir_listing if item.startswith(symlink_dir_prefix)]

        # Loop over a copy of the list and make sure these are actually directories.
        # This will mean that we can have files that are named "symlink_dir_prefix" something and
        # will properly ignore those.
        for thing in prefix_dir_listing[:]:
            if not os.path.isdir(os.path.join(symlink_parent_dir, thing)):
                prefix_dir_listing.remove(thing)

        # The length of the list should be the next available number.
        return '{}{}'.format(symlink_dir_prefix, len(prefix_dir_listing))

    def ensure_symlink_exists(self, original_file_path, symlink_parent_dir, symlink_dir_prefix):
        """ This function will create the next available symlink directory (e.g.: email0 or sample3)
            inside the parent directory if a symlink does not already exist. It returns the path
            to the symlink directory if it creates one, otherwise it returns None. """

        self.logger.debug('Making sure symlink exists for {}: {}'.format(symlink_dir_prefix, original_file_path))

        if os.path.isfile(symlink_parent_dir):
            symlink_parent_dir = os.path.dirname(symlink_parent_dir)

        # Continue if a symlink to this file does not already exist somewhere in the parent directory.
        existing_symlink_path = self.find_all_symlinked_paths(original_file_path, symlink_parent_dir)
        if not existing_symlink_path:

            # Get the next available symlink directory name in the parent directory.
            symlink_dir_name = self.get_next_symlink_dir_name(symlink_parent_dir, symlink_dir_prefix)

            # Build the full path to the new symlink directory.
            symlink_dir_path = os.path.join(symlink_parent_dir, symlink_dir_name)

            # Build the full path to the new symlink.
            if symlink_dir_prefix == 'email':
                symlink_path = os.path.join(symlink_dir_path, 'smtp.stream')
            else:
                symlink_path = os.path.join(symlink_dir_path, os.path.basename(original_file_path))

            # Create the symlink directory.
            try:
                os.makedirs(symlink_dir_path)
            except:
                self.logger.exception('Unable to create symlink directory: {}'.format(symlink_dir_path))

            # Create the symlink to the file.
            try:
                os.symlink(original_file_path, symlink_path)
            except:
                self.logger.exception('Unable to create symlink: {}'.format(symlink_path))

            self.logger.debug('Symlinked to {}: {}'.format(symlink_dir_prefix, original_file_path))

            return symlink_dir_path

        return existing_symlink_path

    def find_indicators(self, original_file_path):
        """ This function matches the good indicators from the Indicator Summary table with the original file path. """

        matching_indicators = []

        # Loop over each good indicator in the Indicator Summary table.
        for g in self.indicator_summary_table:

            # Loop over all of the indicators in the event JSON.
            for i in self.event_json['indicators']:

                # Slightly tweak the check for URL indicators that came from ACE alerts. Since ACE knows the
                # "base_url", it is able to fix the relative URLs in HTML files and report those full URLs
                # in the alerts. The HTML saved in the alert directory still contains the relative links, so
                # for now the best we can do is to add indicators that came from a "data.json" path to the
                # event indicators.csv file. We can do this by matching indicator paths that have "data.json"
                # in them (ACE indicators) with the original_file_path of '' (event level indicators).
                if i['path'].endswith('data.json') and original_file_path == '' and i['type'] == g['type'] and i['value'] == g['value']:
                    matching_indicators.append(i)

                # The indicator matches if the path, type, and value are the same.
                if i['path'] == original_file_path and i['type'] == g['type'] and i['value'] == g['value']:
                    matching_indicators.append(i)
                # If only the type and value are the same, check if the paths point to the same file.
                # This extra check is in here specifically for the sandboxed sample indicators since the
                # indicator JSON might have a different path listed than what we were given here.
                elif original_file_path and i['path'] and i['type'] == g['type'] and i['value'] == g['value']:

                    # This checks if the two file paths are functionally the same file.
                    if filecmp.cmp(i['path'], original_file_path):
                        matching_indicators.append(i)

        return matching_indicators
