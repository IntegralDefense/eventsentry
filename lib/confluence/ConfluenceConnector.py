from bs4 import BeautifulSoup
import json
import logging
import os
import requests
import configparser

from lib.constants import HOME_DIR

class ConfluenceConnector():
    def __init__(self):
        # Initiate logging.
        self.logger = logging.getLogger()
        
        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
           
        # Check if we are verifying requests.
        if self.config['production']['verify_requests'].lower() == 'true':
            self.requests_verify = True
        
            # Now check if we want to use a custom CA cert to do so.
            if 'verify_requests_cert' in self.config['production']:
                self.requests_verify = self.config['production']['verify_requests_cert']
        else:
            self.requests_verify = False

        # Load the API URL from the config if we need to.
        self.api_url = self.config['production']['confluence_api_url']
        
        # Load the space key from the config if we need to.
        self.space_key = self.config['production']['confluence_space_key']
        
        # Load the login credentials.
        self.username = self.config['production']['confluence_user']
        self.password = self.config['production']['confluence_pass']

    def _validate_request(self, request, error_msg='There was an error with the query.'):
        if request.status_code == 200:
            return True
        else:
            self.logger.critical(error_msg)
            self.logger.critical(request.text)

