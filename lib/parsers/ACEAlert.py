import json
import logging
import os
import configparser

from lib.constants import HOME_DIR
from lib.indicator import make_url_indicators


class ACEAlert:
    def __init__(self, alert_path):
        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # Start logging.
        self.logger = logging.getLogger()

        # Read the alert JSON.
        with open(alert_path) as a:
            self.ace_json = json.load(a)

        self.alert_dir = os.path.dirname(alert_path)
        self.path = alert_path
        self.time = self.ace_json['event_time']
        self.tool = self.ace_json['tool']
        self.type = self.ace_json['type']
        self.name = self.ace_json['uuid']
        self.description = self.ace_json['description']
        try:
            self.company_name = self.ace_json['company_name']
        except:
            self.company_name = 'legacy'

        # Load the URL from the config file.
        self.url = self.config['production']['ace_alert_url'] + self.name

        """
        #
        # USER ANALYSIS
        #
        """
        # Try and find any user analysis files.
        user_analysis_files = self.get_all_analysis_paths('saq.modules.user:EmailAddressAnalysis')

        # Parse any user_analysis_files.
        self.user_analysis = []
        for file in user_analysis_files:
            if os.path.exists(os.path.join(self.alert_dir, '.ace', file)):
                with open(os.path.join(self.alert_dir, '.ace', file)) as j:
                    json_data = json.load(j)

                    user = {'cn': '',
                            'displayName': '',
                            'mail': '',
                            'title': '',
                            'description': '',
                            'department': '',
                            'company': '',
                            'distinguishedName': ''}

                    try: user['cn'] = json_data['cn']
                    except: pass

                    try: user['displayName'] = json_data['displayName']
                    except: pass

                    try: user['mail'] = json_data['mail']
                    except: pass

                    try: user['title'] = json_data['title']
                    except: pass

                    try: user['description'] = ' | '.join(json_data['description'])
                    except: pass

                    try: user['department'] = json_data['department']
                    except: pass

                    try: user['company'] = json_data['company']
                    except: pass

                    try: user['distinguishedName'] = json_data['distinguishedName']
                    except: pass

                    self.user_analysis.append(user)

        """
        #
        # URLS
        #
        """
        # Save whatever URLs ACE was able to automatically extract.
        urls = set()
        url_files = self.get_all_analysis_paths('saq.modules.file_analysis:URLExtractionAnalysis')
        for file in url_files:
            with open(os.path.join(self.alert_dir, '.ace', file)) as j:
                json_data = json.load(j)
                for url in json_data:
                    if url.endswith('/'):
                        url = url[:-1]
                    urls.add(url)
        self.urls = sorted(list(urls))

        # Make indicators from the URLs.
        self.indicators = make_url_indicators(self.urls)

        """
        #
        # SCREENSHOTS
        #
        """
        screenshots = set()
        for observable in self.ace_json['observable_store'].keys():
            try:
                if 'screenshot' in self.ace_json['observable_store'][observable]['tags']:
                    screenshot_path = os.path.join(self.alert_dir, self.ace_json['observable_store'][observable]['value'])
                    screenshots.add(screenshot_path)
                    self.logger.debug('Found ACE screenshot: {}'.format(screenshot_path))
            except:
                pass
        self.screenshots = sorted(list(screenshots))

        """
        #
        # TAGS
        #
        """
        tags = set()
        for observable in self.ace_json['observable_store'].keys():
            try:
                for tag in self.ace_json['observable_store'][observable]['tags']:
                    tags.add(tag)
            except:
                pass
        self.tags = sorted(list(tags))
        self.logger.debug('"{}" alert has these tags: {}'.format(self.name, self.tags))

    @property
    def json(self):
        """ Return a JSON compatible view of the ACE alert. """

        json = {}
        json['alert_dir'] = self.alert_dir
        json['company_name'] = self.company_name
        json['description'] = self.description
        json['name'] = self.name
        json['path'] = self.path
        json['screenshots'] = self.screenshots
        json['tags'] = self.tags
        json['time'] = self.time
        json['tool'] = self.tool
        json['type'] = self.type
        json['url'] = self.url
        json['urls'] = self.urls
        json['user_analysis'] = self.user_analysis

        return json

    def get_all_analysis_paths(self, ace_module):
        analysis_paths = []

        # Loop over each observable in the alert.
        for observable in self.ace_json['observable_store'].keys():
            # See if there is an analysis for the given ACE module.
            try:
                json_file = self.ace_json['observable_store'][observable]['analysis'][ace_module]['details']['file_path']
                if json_file:
                    analysis_paths.append(self.ace_json['observable_store'][observable]['analysis'][ace_module]['details']['file_path'])
            except:
                pass

        return analysis_paths
