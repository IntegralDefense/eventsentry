from bs4 import BeautifulSoup
import json
import logging
import os
import requests
import configparser

from lib.config import config, verify_requests
from lib.constants import HOME_DIR

class ConfluenceConnector():
    def __init__(self):
        # Initiate logging.
        self.logger = logging.getLogger()
        
        # Load the API URL from the config if we need to.
        self.api_url = config['wiki']['confluence']['confluence_api_url']
        
        # Load the space key from the config if we need to.
        self.space_key = config['wiki']['confluence']['confluence_space_key']
        
        # Load the login credentials.
        self.username = config['wiki']['confluence']['confluence_user']
        self.password = config['wiki']['confluence']['confluence_pass']

        # Store the verify requests config setting.
        self.verify_requests = verify_requests

    def _validate_request(self, request, error_msg='There was an error with the query.'):
        if request.status_code == 200:
            return True
        else:
            self.logger.critical(error_msg)
            self.logger.critical(request.text)

