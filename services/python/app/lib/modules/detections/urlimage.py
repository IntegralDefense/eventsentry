import hashlib
import shlex
import subprocess
import tempfile

from lib.constants import PROXYCHAINS
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Use this user-agent when downloading the images.
        user_agent = self.config['user_agent']

        # Store the hashes in a dictionry of dict[md5] = url
        image_hashes = {}

        # Download and hash any URL with any of these in them.
        image_extensions = self.config['image_extensions']

        # Loop over the unique URLs to download and hash any images.
        for url in set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'URI - URL']):
            # Stupid hack for WeTransfer emails that have hundreds of images.
            if not 'wetransfer.net' in url and not 'wetransfer.com' in url:
                if any(ext.lower() in url.lower() for ext in image_extensions):
                    try:
                        temp = tempfile.NamedTemporaryFile()
                        command = '{} wget -O {} -U {} -T {} -t {} {}'.format(PROXYCHAINS, temp.name, shlex.quote(user_agent), 5, 1, shlex.quote(url))
                        subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        with open(temp.name, 'rb') as image:
                            m = hashlib.md5()
                            m.update(image.read())
                            md5 = m.hexdigest().lower()
                            image_hashes[md5] = url
                    except:
                        self.logger.exception('Error downloading image: {}'.format(url))

        # Loop over each item in the config file.
        for item in self.config['items']:

            try:
                # Load this particular image config.
                hashes = self.config['items'][item]['hashes']
                tags = self.config['items'][item]['tags']
                mode = self.config['items'][item]['mode'].lower()

                if mode == 'all':
                    if all(h.lower() in image_hashes for h in hashes):
                        for h in hashes:
                            self.detections.append('Detected the {} image: {}'.format(item, image_hashes[h]))
                            self.tags += tags
                elif mode == 'any':
                    for h in hashes:
                        if h.lower() in image_hashes:
                            self.detections.append('Detected the {} image: {}'.format(item, image_hashes[h]))
                            self.tags += tags
            except:
                self.logger.exception('Error running the {} {} detection module'.format(item, self.name))
