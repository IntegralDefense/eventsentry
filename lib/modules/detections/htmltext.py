import html
import urllib
from bs4 import BeautifulSoup

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Keep a record of the HTML file's MD5 hash so we only loop over unique files.
        md5_cache = []

        # Loop over all of the HTML files in the event.
        for h in [f for f in self.event_json['files'] if f['category'] == 'html']:

            # Continue if we haven't already processed this MD5.
            if not h['md5'] in md5_cache:

                # Add the MD5 to the cache.
                md5_cache.append(h['md5'])

                # Read the contents of the HTML file.
                with open(h['path'], encoding='utf-8', errors='ignore') as f:
                    file_text = f.read()
                    
                    # Store different forms of the HTML text.
                    texts = []
                    texts.append(file_text)
                    try:
                        texts.append(str(BeautifulSoup(urllib.parse.unquote(file_text), 'lxml')))
                    except:
                        pass
                    try:
                        texts.append(html.unescape(file_text))
                    except:
                        pass

                    # Run the detections for each form of the HTML text we have.
                    for text in texts:

                        text = text.lower()

                        # Loop over each section in the config file.
                        for section in self.config.sections():

                            try:
                                # Load this particular HTML config.
                                delimeter = self.config.get(section, 'delimeter')
                                strings = self.config.get(section, 'strings').split(delimeter)
                                tags = self.config.get(section, 'tags').split(',')
                                mode = self.config.get(section, 'mode').lower()

                                if mode == 'all':
                                    if all(s.lower() in text for s in strings):
                                        self.detections.append('Detected the {} HTML by text "{}": {}'.format(section, strings, h['path']))
                                        self.tags += tags
                                elif mode == 'any':
                                    for s in strings:
                                        if s.lower() in text:
                                            self.detections.append('Detected the {} HTML by text "{}": {}'.format(section, s, h['path']))
                                            self.tags += tags
                            except:
                                self.logger.exception('Error running the {} {} detection module'.format(section, self.name)) 
