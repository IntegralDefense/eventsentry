import hashlib
import shlex
import subprocess
import tempfile

from lib.constants import PROXYCHAINS, PROXYCHAINS_CONFIG
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Use this user-agent when downloading the images.
        user_agent = self.config.get('global', 'user_agent')

        # Store the hashes in a dictionry of dict[md5] = url
        image_hashes = {}

        # Download and hash any URL with any of these in them.
        image_extensions = self.config.get('global', 'image_extensions').split(',')

        # Loop over the unique URLs to download and hash any images.
        for url in set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'URI - URL']):
            if any(ext.lower() in url.lower() for ext in image_extensions):
                try:
                    temp = tempfile.NamedTemporaryFile()
                    command = '{} -f {} wget -O {} -U {} -T {} {}'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, temp.name, shlex.quote(user_agent), 5, shlex.quote(url))
                    subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    with open(temp.name, 'rb') as image:
                        m = hashlib.md5()
                        m.update(image.read())
                        md5 = m.hexdigest().lower()
                        image_hashes[md5] = url
                except:
                    self.logger.exception('Error downloading image: {}'.format(url))

        # Loop over each section in the config file.
        for section in self.config.sections():

            # Skip the section if it is the global section.
            if section == 'global':
                continue

            try:
                # Load this particular image config.
                hashes = self.config.get(section, 'hashes').split(',')
                tags = self.config.get(section, 'tags').split(',')
                mode = self.config.get(section, 'mode').lower()

                if mode == 'all':
                    if all(h.lower() in image_hashes for h in hashes):
                        for h in hashes:
                            self.detections.append('Detected the {} image: {}'.format(section, image_hashes[h]))
                            self.tags += tags
                elif mode == 'any':
                    for h in hashes:
                        if h.lower() in image_hashes:
                            self.detections.append('Detected the {} image: {}'.format(section, image_hashes[h]))
                            self.tags += tags
            except:
                self.logger.exception('Error running the {} {} detection module'.format(section, self.name))
