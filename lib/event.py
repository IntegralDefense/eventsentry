import configparser
import hashlib
import importlib
import json
import logging
import os
import re
import requests
import shutil
import subprocess
import sys
import tempfile

from flockcontext import FlockOpen
from urltools import find_urls

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.dirname(__file__)
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

from lib.constants import HOME_DIR
from lib.file import File
from lib.parsers import ACEAlert
from lib.parsers import BaseSandboxParser
from lib.parsers import CuckooParser
from lib.parsers import EmailParser
from lib.indicator import make_url_indicators
from lib.parsers import VxstreamParser
from lib.parsers import WildfireParser
from lib.eventwhitelist import EventWhitelist


class Event():
    def __init__(self, ace_id, name, mongo_connection, debug=False):
        """
        An 'event' as we define it is a collection of 'critical files' and the
        intel associated with them. I consider the following items to be the
        critical files:

            * ACE alerts (data.json)
            * Emails (rfc822 files)
            * HTML files (mostly used for creds harvesting)
            * Sandbox reports (Cuckoo/VxStream/Wildfire)

        The Event objects are created automatically by the event sentry process
        that runs as an infinite loop in the background. It queries the ACE
        database for open events and the alerts associated with them. When the
        Event object is created, it will:

            * Load the event.json file if it exists. Otherwise it will use the template copy.
            * Create an event directory if necessary
            * Rsync new alerts from ACE to the event directory/delete alerts removed from the event
            * Walk the event directory to identify critical files

        If any of the critical files have changed or we are forcing an update, it will:

            * Parse the critical files (which creates indicators)
            * Check what was parsed against the CRITS whitelist
            * Clean up the indicators with additional logic that doesn't fit inside CRITS
            * Perform WHOIS lookups for non-whitelisted domains
            * Run all of the event detection modules
            * Create the event package
        """

        # Validate the event name. We will accept names in these forms:
        # 20160101_test_event
        # 20160101 test event
        if not re.match(r'^[0-9]{8}(_| )', name):
            raise ValueError(
                'Event name does not match naming convention of YYYYMMDD_event_name or "YYYYMMDD event name"')

        # Set the ACE event ID.
        self.ace_id = ace_id

        # Set the event name first. This is required in order to create the log file.
        self.name_disk = name.replace(' ', '_')
        self.name_wiki = name.replace('_', ' ')

        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # Set up logging.
        log_path = os.path.join(HOME_DIR, 'logs', '{}.log'.format(self.name_disk))
        if debug:
            logging.basicConfig(filename=log_path, level=logging.DEBUG, format='[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s] - %(message)s')
        else:
            logging.basicConfig(filename=log_path, level=logging.INFO, format='[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s] - %(message)s')
        self.logger = logging.getLogger()

        # Set the NO_PROXY variable.
        try:
            no_proxy_domains = self.config['production']['no_proxy_domains']
            os.environ['NO_PROXY'] = no_proxy_domains
            self.logger.debug('Setting NO_PROXY for: {}'.format(no_proxy_domains))
        except:
            pass

        # Set up some paths.
        path_prefix = self.config['production']['event_path_prefix']
        self.path = os.path.join(path_prefix, self.name_disk)
        self.crits_path = os.path.join(self.path, '.crits')

        # Save the CRITS Mongo connection.
        self.mongo_connection = mongo_connection

        # Load the event JSON. If it does not exist, a default copy will be used.
        self.json_path = os.path.join(self.path, 'event.json')
        self.json = self.load_json(self.json_path)

        # Save the event path to the JSON.
        self.json['path'] = self.path

        # Flag to note whether or not a critical file has changed. This will
        # trigger a full wiki update and a rewrite of the .crits directory.
        self.changed = False

    def setup(self, alert_paths=[], manual_indicators=[], force=False):
        """ Parse everything in the event directory to build the event.json """

        if alert_paths:
            # Make sure the event directory exists.
            if not os.path.exists(self.path):
                #os.makedirs(self.path, mode=0o770)
                os.makedirs(self.path)
                self.logger.debug('Created event directory: {}'.format(self.path))

            # Make sure the collect directory exists.
            collect_path = os.path.join(self.path, 'collect')
            if not os.path.exists(collect_path):
                #os.makedirs(collect_path, mode=0o770)
                os.makedirs(collect_path)
                self.logger.debug('Created collect directory: {}'.format(collect_path))

            # Figure out which alerts are new to the event.
            existing_alert_paths = [f['path'] for f in self.json['files'] if f['category'] == 'ace_alert']
            new_alert_paths = []
            for alert_path in alert_paths:
                uuid = os.path.basename(alert_path)
                if not any(uuid in existing_path for existing_path in existing_alert_paths):
                    new_alert_paths.append(alert_path)

            # Rsync any new alert paths we were given.
            self.rsync_alerts(new_alert_paths)

            # Figure out if any alerts were removed from the event.
            for a in existing_alert_paths:
                uuid = a.split('/')[-2]
                if not any(uuid in alert_path for alert_path in alert_paths):
                    self.logger.warning('Alert has been removed from the ACE event: {}'.format(uuid))
                    try:
                        shutil.rmtree(os.path.dirname(a))
                    except:
                        self.logger.exception('There was an error trying to delete alert from event: {}'.format(os.path.dirname(a)))

        # Identify the files in the event directory.
        self.logger.debug('Starting to walk event directory.')
        files = self.walk_event_directory()
        self.logger.debug('Finished walking event directory.')

        # Cross reference the critical files with what is stored in the JSON
        # to see if there have been any changes. Changes to critical files are
        # what require the event to be reprocessed.
        if force or self.has_critical_file_changed(files):
            self.logger.info('A critical file has changed or we are forcing an update. Reprocessing the event.')

            # Get rid of the old event campaign and tags.
            self.json['campaign'] = {}
            self.json['tags'] = []

            # Flag the event as changed.
            self.changed = True

            # Save the current version of the files to the JSON.
            self.json['files'] = files

            # Fill in the missing non-critical file MD5 hashes. We don't hash every
            # file as we originally walk through the event directory to save time.
            # We only need to hash the critical files when walking the event directory
            # so that we can make sure that we do not have any duplicates and so we
            # can also tell if any of them have changed. This makes things much faster
            # if nothing has changed with the event.
            for f in self.json['files']:
                if not f['critical']:
                    f['md5'] = self.calculate_md5(f['path'])

            # Get the latest whitelist from CRITS.
            whitelist = EventWhitelist(mongo_connection=self.mongo_connection)

            # Parse the ACE alerts.
            ace_alerts = self.parse_ace_alerts()
            self.json['ace_alerts'] = [ace_alert.json for ace_alert in ace_alerts]

            # Gather up the unique screenshots found in the ACE alerts. Right now these are just from Cloudphish.
            screenshot_dict = {}
            for ace_alert in ace_alerts:
                for screenshot in ace_alert.screenshots:
                    # Skip this screenshot if it is an HTML e-mail body. The HTML e-mail screenshots
                    # are handled within the EmailParser class.
                    if 'text_html' in screenshot:
                        continue

                    # Find the MD5 hash of this screenshot.
                    for f in self.json['files']:
                        if f['path'] == screenshot:
                            screenshot_dict[f['md5']] = f['path']

            # Symlink to the screenshots so we can ensure they have unique file names.
            unique_screenshots = []
            for md5 in screenshot_dict:
                new_name = 'ace_screenshot_{}.png'.format(md5)
                new_path = os.path.join(self.path, new_name)
                unique_screenshots.append(new_path)
                if not os.path.exists(new_path):
                    self.logger.debug('Symlinking to ACE screenshot: {}'.format(screenshot_dict[md5]))
                    os.symlink(screenshot_dict[md5], new_path)

            # Save the screenshots to the event JSON.
            self.json['ace_screenshots'] = sorted(unique_screenshots)

            # Parse the emails and make their indicators.
            emails = self.parse_emails(whitelist)
            self.json['emails'] = [email.json for email in emails]

            # Symlink to the sreenshots in the emails so we can ensure they have unique file names.
            for email in self.json['emails']:

                # Locate the MD5 of this email.
                for f in self.json['files']:
                    if f['path'] == email['path']:

                        # Symlink (rename) each screenshot in this email.
                        new_screenshot_paths = []
                        for screenshot in email['screenshots']:
                            new_name = 'email_screenshot_{}_{}'.format(f['md5'], os.path.basename(screenshot))
                            new_path = os.path.join(os.path.dirname(email['path']), new_name)
                            new_screenshot_paths.append(new_path)
                            if not os.path.exists(new_path):
                                self.logger.debug('Symlinking to email screenshot: {}'.format(screenshot))
                                os.symlink(screenshot, new_path)

                        # Replace the screenshot paths in the JSON with the new paths.
                        email['screenshots'] = sorted(new_screenshot_paths)

            # Parse the sandbox reports and make their indicators.
            sandbox_reports = self.parse_sandbox_reports(whitelist)
            self.json['sandbox'] = [sandbox_report.json for sandbox_report in sandbox_reports]

            # The EmailParser objects do not know where the attachments are located within the event directory.
            # This is a handy piece of information for various processes later, such as making the .crits intel directory.
            for email in self.json['emails']:
                for attachment in email['attachments']:
                    attachment['event_path'] = ''

                    # Try to locate the file with the same MD5.
                    for f in self.json['files']:
                        if f['md5'] == attachment['md5']:

                            # Inject the event directory path into the e-mail JSON.
                            attachment['event_path'] = f['path']

            # The sandbox reports do not know where the sample is located within the event directory. That
            # is a handy piece of information for various processes later, such as making the .crits intel directory.
            # Also fix the filename in the sandbox reports. VxStream likes to name it after the SHA256 hash
            # and does not appear to included the actual filename anywhere in its JSON report.
            for report in self.json['sandbox']:
                report['event_path'] = ''

                # Try to locate the file with the same MD5.
                for f in self.json['files']:
                    if f['md5'] == report['md5']:

                        # Overwrite the filename in the sandbox report.
                        report['filename'] = os.path.basename(f['path'])

                        # Inject the event directory path into the sandbox report.
                        report['event_path'] = f['path']

                    # Loop over any dropped files in this sandbox report to inject the event path.
                    for dropped_file in report['dropped_files']:
                        if f['md5'] == dropped_file['md5']:
                            # Inject the event directory path into the dropped file JSON.
                            dropped_file['event_path'] = f['path']

            # Gather up the indicators.
            self.json['indicators'] = []

            # Loop over all of the HTML files in the event and pull out the URLs.
            self.logger.debug('Gathering URLs from HTML files in the event.')
            for html_file in [f['path'] for f in self.json['files'] if f['category'] == 'html']:

                # Store the unique URLs we find.
                unique_urls = set()
                
                # Open and read the contents of the file.
                with open(html_file, 'rb') as f:
                    urls = find_urls(f.read())
                    
                    # Add the unique URLs to the list.
                    for url in urls:
                        unique_urls.add(url)
            
                # Create indicators for the URLs.
                indicators = make_url_indicators(unique_urls)
                for indicator in indicators:
                    indicator.path = html_file
                    indicator.whitelisted = whitelist.is_indicator_whitelisted(indicator)
                    self.json['indicators'].append(indicator.json)

            # Gather up the indicators from the ACE alerts.
            self.logger.debug('Checking ACE alert indicators against whitelist.')
            for ace_alert in ace_alerts:
                for indicator in ace_alert.indicators:
                    indicator.path = ace_alert.path
                    indicator.whitelisted = whitelist.is_indicator_whitelisted(indicator)
                    self.json['indicators'].append(indicator.json)

            # Gather up the indicators from the emails.
            self.logger.debug('Checking email indicators against whitelist.')
            for email in emails:
                for indicator in email.indicators:
                    indicator.path = email.path
                    indicator.whitelisted = whitelist.is_indicator_whitelisted(indicator)
                    self.json['indicators'].append(indicator.json)

            # Gather up the indicators from the sandbox reports.
            self.logger.debug('Checking sandbox indicators against whitelist.')
            for sandbox_report in sandbox_reports:
                # Try to find the path to the actual sandboxed sample instead of the JSON report.
                matching_samples = [f for f in self.json['files'] if f['md5'] == sandbox_report.md5]
                if matching_samples:
                    for indicator in sandbox_report.indicators:
                        indicator.path = matching_samples[0]['path']
                        indicator.whitelisted = whitelist.is_indicator_whitelisted(indicator)
                        self.json['indicators'].append(indicator.json)

                else:
                    self.logger.warning('Could not find matching sample for indicators: "{}" "{}"'.format(sandbox_report.filename, sandbox_report.md5))

            # Gather up any manual indicators we were given (from the refresh wiki function).
            # These are not Indicator objects, so we do not add the .json form to the list.
            for indicator in manual_indicators:
                self.logger.debug('Adding manual indicator to JSON: {} - {}'.format(indicator['type'], indicator['value']))
                indicator['path'] = ''
                # We want to allow the Manual Indicators section to bypass the whitelist.
                indicator['whitelisted'] = False 
                self.json['indicators'].append(indicator)

            """
            # Loop over any CSS URLs we found to try and find even more URLs.
            for css_url in [i['value'] for i in self.json['indicators'] if i['type'] == 'URI - URL' and '.css' in i['value']]:
            
                # Download the CSS content and find any URLs inside it.
                try:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.94 Safari/537.36'}
                    css = requests.get(css_url, headers=headers).content
                    css_urls = find_urls(css, base_url=css_url)
                except:
                    self.logger.exception('Unable to download the CSS: {}'.format(css_url))
            """

            # Add some items to the event tags.
            if emails:
                self.json['tags'].append('phish')
            self.json['tags'] = sorted(list(set(self.json['tags'])))

            # Create the event package.
            self.package_event()

    """
    #
    # PACKAGE EVENT
    #
    """
    def package_event(self):
        self.logger.debug('Packaging the event.')

        # Start by making a temporary directory.
        with tempfile.TemporaryDirectory() as temp_dir:
    
            # Make a directory inside the temp directory to hold all the things.
            intel_package_dir = os.path.join(temp_dir, 'intel_' + self.name_disk)
            os.makedirs(intel_package_dir)

            # Copy each e-mail to our directory.
            for i in range(len(self.json['emails'])):
                email_path = self.json['emails'][i]['path']
                filename = 'email{}_{}'.format(i+1, os.path.basename(email_path))
                shutil.copyfile(email_path, os.path.join(intel_package_dir, filename))
                
            # Copy each sandboxed malware sample to our directory.
            # Start by making a separate temporary directory to hold the malware.
            with tempfile.TemporaryDirectory() as temp_malware_dir:
                
                # Make a "malware" directory to hold the samples.
                malware_dir = os.path.join(temp_malware_dir, 'malware')
                os.makedirs(malware_dir)
                
                # Copy each sample to the "malware" directory.
                for sample in self.json['sandbox']:
                    if sample['event_path']:
                        shutil.copyfile(sample['event_path'], os.path.join(malware_dir, sample['filename']))
                        
                # Create a .zip file of the "malware" directory.
                malware_zip_path = os.path.join(intel_package_dir, 'malware.zip')
                malware_zip_password = self.config['production']['malware_zip_password']
                malware_zip_command = '7z a {} -p{} {}/*'.format(malware_zip_path, malware_zip_password, temp_malware_dir)

                self.logger.debug('Creating malware.zip: {}'.format(malware_zip_path))
                self.logger.debug(malware_zip_command)

                try:
                    subprocess.check_call(malware_zip_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                except subprocess.CalledProcessError:
                    # Log and skip over malware.zip if it couldn't be created.
                    self.logger.exception('Could not create malware.zip: {}'.format(malware_zip_path))
            
            # Start with a copy of the event JSON. We want to remove a few things.
            output_json = dict(self.json)
            del output_json['ace_alerts']
            del output_json['ace_id']
            del output_json['ace_screenshots']
            del output_json['campaign']
            del output_json['files']
            del output_json['whois']
            del output_json['wiki_name']
            del output_json['wiki_version']

            # Write the event.json to disk.
            with open(os.path.join(intel_package_dir, 'event.json'), 'w') as json_data:
                json.dump(output_json, json_data)
                    
            # Now that everything is copied or written to the temp directory, zip it up.
            intel_package_zip_path = os.path.join(self.path, 'intel_{}.zip'.format(self.name_disk))
            
            # See if the intel package already exists... If so delete it and make a new one.
            if os.path.exists(intel_package_zip_path):
                self.logger.debug('Deleting old intel package: {}'.format(intel_package_zip_path))
                os.remove(intel_package_zip_path)
            
            # Create the new intel package.
            intel_zip_password = self.config['production']['intel_zip_password']
            intel_zip_command = '7z a {} -p{} {}/*'.format(intel_package_zip_path, intel_zip_password, temp_dir)

            try:
                self.logger.debug('Creating intel package: {}'.format(intel_package_zip_path))
                self.logger.debug(intel_zip_command)
                subprocess.check_call(intel_zip_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            except subprocess.CalledProcessError:
                # Log and skip over the intel package if it couldn't be created.
                self.logger.exception('Could not create intel package: {}'.format(intel_package_zip_path))

    """
    #
    # WHOIS LOOKUPS
    #
    """

    def whois_lookups(self):
        """ This function performs WHOIS lookups for all the non-whitelisted domains. """

        self.logger.debug('Performing WHOIS lookups.')

        whois = []
        # whois = [ {'domain': domain.com, 'email': registrant_email, 'raw': <whois output>} ]

        # Loop over each unique and non-whitelisted domain indicator.
        for domain in set([i['value'] for i in self.json['indicators'] if not i['whitelisted'] and i['type'] == 'URI - Domain Name']):
            try:

                # Only continue if this domain is not already in the event JSON.
                if not any(w['domain'] == domain for w in self.json['whois']):
                    self.logger.debug('Checking WHOIS for domain: {}'.format(domain))

                    # Perform the WHOIS lookup.
                    results = {'domain': '', 'email': '', 'raw': ''}
                    output = subprocess.check_output(['proxychains', 'whois', domain]).decode('utf-8')

                    # Continue if the output has an e-mail address in it.
                    if 'Registrant Email:' in output:
                        output = output.splitlines()

                        # Clean up the output by only including certain lines.
                        include_these_lines = ['Domain name:', 'Domain Name:', 'Updated Date:', 'Creation Date:',
                                               'Registry Expiry Date:', 'Registrant ', 'Name Server:']
                        output = [' '.join(line.split()) for line in output if
                                  any(line.startswith(item) for item in include_these_lines)]

                        # Try and extract the registrant e-mail address from the output.
                        try:
                            registrant_regex = re.compile(r'Registrant Email: (.*)')
                            for line in output:
                                if 'Registrant Email:' in line:
                                    email = registrant_regex.search(line).group(1)
                                    if '@' in email:
                                        results['email'] = email
                        except:
                            pass

                    # Join the output lines into a single string and add it to the list.
                    results['domain'] = domain
                    results['raw'] = '\n'.join(output)
                    whois.append(results)
                # This domain is already in the event JSON.
                else:
                    self.logger.debug('Skipping WHOIS lookup for domain that already exists: {}'.format(domain))
            except:
                self.logger.error('Unable to get WHOIS for domain: {}'.format(domain))

        # Save all of the WHOIS results to the event JSON.
        self.json['whois'] += whois

    """
    #
    # CLEAN INDICATORS
    #
    """

    def clean_indicators(self):
        """ This function dynamically loads all of the cleanindicators modules. """

        cleanindicators_modules = os.listdir(os.path.join(this_dir, 'modules', 'cleanindicators'))

        for file in cleanindicators_modules:
            if file.endswith('.py'):
                name = file[:-3]
                try:
                    module = importlib.import_module('modules.cleanindicators.{}'.format(name))
                    module.run(self.json)
                except:
                    self.logger.exception('Unable to run cleanindicators module: {}'.format(file))

    """
    #
    # EVENT DETECTIONS
    #
    """

    def event_detections(self, good_indicators):
        """ This function dynamically loads all of the detection modules. """

        all_tags = []
        all_detections = []
        all_extra = []

        detection_modules = os.listdir(os.path.join(this_dir, 'modules', 'detections'))

        # Load the detection module config file.
        config_path = os.path.join(this_dir, 'modules', 'detections', 'etc', 'local', 'config.ini')
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
        except:
            self.logger.error('Error loading detection module config.ini at: {}'.format(config_path))
            config = None

        for file in detection_modules:
            if file.endswith('.py'):
                name = file[:-3]
                try:
                    module = importlib.import_module('modules.detections.{}'.format(name))
                    tags, detections, extra = module.run(config, self.json, good_indicators)
                    all_tags += tags
                    all_detections += detections
                    all_extra += extra
                except:
                    self.logger.exception('Unable to run detection module: {}'.format(file))

        self.json['tags'] = sorted(list(set(self.json['tags'] + all_tags)))
        self.json['detections'] = sorted(list(set(all_detections)))
        self.json['detections_extra'] = sorted(list(set(all_extra)))

    """
    #
    # CRITICAL FILE PARSING FUNCTIONS
    #
    """

    def parse_ace_alerts(self):
        """ Parses the ACE alerts found in the event directory. """

        ace_alerts = []
        ace_alert_paths = [f['path'] for f in self.json['files'] if f['category'] == 'ace_alert']
        for ace_alert_path in ace_alert_paths:
            ace_alerts.append(ACEAlert.ACEAlert(ace_alert_path))
        return sorted(ace_alerts, key=lambda x: x.time)

    def parse_emails(self, whitelist):
        """ Parse the emails found in the event directory. """

        emails = []
        email_paths = [f['path'] for f in self.json['files'] if f['category'] == 'email']
        for email_path in email_paths:
            emails.append(EmailParser.EmailParser(email_path, whitelist))
        
        # Dedup the parsed e-mails. We want to prefer the ones with the original_recipient set.
        unique_emails = []
        for email in emails:

            # Prefer the messages with the original_recipient value set.
            if email.original_recipient:
                if not any(e.message_id == email.message_id and e.original_recipient == email.original_recipient for e in unique_emails):
                    self.logger.debug('Found unique original_recipient e-mail: {}'.format(email.path))
                    unique_emails.append(email)

        # Loop over the parsed e-mails again to get unique e-mails without original_recipient.
        for email in emails:

            # If there is no original_recipient, it likely means this email came from a
            # POTENTIAL PHISH report, and the phish report rfc822 message has the original_recipient
            # but the original embedded email does not.
            if not email.original_recipient:
                if not any(e.message_id == email.message_id and e.to_addresses == email.to_addresses for e in unique_emails):
                    self.logger.debug('Found unique NON original_recpient e-mail: {}'.format(email.path))
                    unique_emails.append(email)
          
        return sorted(unique_emails, key=lambda x: x.received_time)

    def parse_sandbox_reports(self, whitelist):
        """ Parse the sandbox reports found in the event directory. """

        # List to store all of the parsed reports.
        reports = []

        # Parse all of the Cuckoo reports.
        cuckoo_paths = [f['path'] for f in self.json['files'] if f['category'] == 'cuckoo']
        for path in cuckoo_paths:
            reports.append(CuckooParser.CuckooParser(path))

        # Parse all of the VxStream reports.
        vxstream_paths = [f['path'] for f in self.json['files'] if f['category'] == 'vxstream']
        for path in vxstream_paths:
            reports.append(VxstreamParser.VxstreamParser(path))

        # Parse all of the Wildfire reports.
        wildfire_paths = [f['path'] for f in self.json['files'] if f['category'] == 'wildfire']
        for path in wildfire_paths:
            reports.append(WildfireParser.WildfireParser(path))

        # Organize the flat report list by sample MD5.
        reports_dict = {}
        for report in reports:
            if not report.json['md5'] in reports_dict:
                reports_dict[report.json['md5']] = []
            reports_dict[report.json['md5']].append(report)

        # Now merge the reports that have the same sample MD5.
        generic_reports = []
        for md5 in reports_dict:
            try:
                generic_report = BaseSandboxParser.dedup_reports(reports_dict[md5], whitelist)
                generic_reports.append(generic_report)
                self.logger.debug('Made generic sandbox report for {} ({})'.format(generic_report.md5,
                                                                                   generic_report.filename))
            except:
                self.logger.exception('There was an error making a generic sandbox report for sample {}'.format(md5))

        return generic_reports

    """
    #
    # EVENT STRUCTURE FUNCTIONS
    #
    """

    def calculate_md5(self, path):
        """ Calculates the MD5 hash of the file. It returns
        the 'empty' MD5 hash if there were any exceptions. """

        try:
            md5 = hashlib.md5()
            with open(path, 'rb') as f:
                md5.update(f.read())

            return md5.hexdigest()
        except:
            return 'd41d8cd98f00b204e9800998ecf8427e'

    def has_critical_file_changed(self, files):
        """ Determine if the event needs to be reprocessed by cross
        checking the critical files found in the event directory
        with what was last stored in the event.json file. """

        # Find the critical files that were just identified in the event directory.
        critical_files = [f['path'] for f in files if f['critical']]
        critical_md5s = [f['md5'] for f in files if f['critical']]

        # Find the critical files that were previously stored in the JSON.
        json_critical_files = [f['path'] for f in self.json['files'] if f['critical']]
        json_critical_md5s = [f['md5'] for f in self.json['files'] if f['critical']]

        # Compare critical files with the JSON. This identifies new files.
        for critical_file in critical_files:
            if not critical_file in json_critical_files:
                self.logger.debug('Found new critical file: {}'.format(critical_file))
                return True

        # Compare critical file MD5s with the JSON. This identifies updated files.
        for critical_md5 in critical_md5s:
            if not critical_md5 in json_critical_md5s:
                self.logger.debug('Critical file has updated hash: {}'.format(critical_md5))
                return True

        # Compare the JSON critical files with the critical files that were just identified. This identifies deleted files.
        for json_critical_file in json_critical_files:
            if not json_critical_file in critical_files:
                self.logger.debug('Found deleted critical file: {}'.format(json_critical_file))
                return True

        return False

    def walk_event_directory(self):
        """ Walk the event directory to identify the files.
        Critical files include: ACE alerts, emails, sandbox reports,
        and HTML files. """

        event_files = set()

        # Walk the event directory searching for critical files.
        for root, dirs, files in os.walk(self.path):
            for f in files:
                try:
                    full_path = os.path.join(root, f)

                    # There are some files/paths we want to skip.
                    skip_these_things = self.config['production']['bad_structure_paths'].split(',')
                    if any(bad_path in full_path for bad_path in skip_these_things):
                        continue

                    # Create a file object from the path.
                    f = File(full_path)

                    # Add the JSON form of the file to the list.
                    event_files.add(f)
                except PermissionError:
                    pass
                except FileNotFoundError:
                    pass

        # Return the JSON form of each file.
        return [f.json for f in event_files]

    def rsync_alerts(self, alert_paths):
        """ Uses rsync to copy a list of ACE alert paths to the event directory. """

        ace_server = self.config['production']['ace_server']
        ace_ssh_user = self.config['production']['ace_ssh_user']
        ace_ssh_key = self.config['production']['ace_ssh_key']
        ace_alert_root = self.config['production']['ace_alert_root']

        for alert_path in alert_paths:
            remote_alert_path = os.path.join(ace_alert_root, alert_path)

            #rsync_command = "rsync -r -e 'ssh -i " + ace_ssh_key + "' " + ace_ssh_user + "@" + ace_server + ":" + remote_alert_path + " " + self.path
            rsync_command = "rsync --timeout=3 -r -e 'ssh -i {}' {}@{}:{} {}".format(ace_ssh_key, ace_ssh_user, ace_server, remote_alert_path, self.path)

            self.logger.debug("Rsyncing alert: " + alert_path)

            try:
                subprocess.check_call(rsync_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
            except subprocess.CalledProcessError:
                # Log and skip over the alert if it couldn't be copied.
                self.logger.error("Could not rsync alert: " + alert_path)
                self.logger.error(rsync_command)

    """
    #
    # EVENT JSON FUNCTIONS
    #
    """

    def load_json(self, path):
        """ Loads the event.json file. If it does not exist or
        there was an exception, it will return the default json. """

        try:
            with open(path) as j:
                self.logger.debug('Loading existing event JSON.')
                return json.load(j)
        except:
            self.logger.debug('JSON not found. Using template instead.')
            j = {'ace_alerts': [],
                 'ace_id': self.ace_id,
                 'campaign': {},
                 'detections': [],
                 'detections_extra': [],
                 'emails': [],
                 'files': [],
                 'indicators': {},
                 'name': self.name_disk,
                 'path': '',
                 'sandbox': [],
                 'tags': [],
                 'whois': [],
                 'wiki_name': self.name_wiki,
                 'wiki_version': ''}
            return j

    def write_json(self):
        """ Writes the event.json file. """

        try:
            # Acquire a lock and write the JSON.
            with FlockOpen(os.path.join(self.path, 'event.json'), 'w') as lock:
                try:
                    json.dump(self.json, lock.fd)
                except:
                    lock.fd.write(str(self.json))
                    self.logger.critical('Check this bad JSON! {}'.format(self.path + '/event.json'))
        except:
            self.logger.exception('Could not write event JSON!')
