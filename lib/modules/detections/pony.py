import hashlib
import shlex
import subprocess
import tempfile

from lib.modules.DetectionModule import *

from lib.constants import PROXYCHAINS, PROXYCHAINS_CONFIG

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Use this user-agent when downloading the images.
        user_agent = self.config.get('global', 'user_agent')

        # These are observed Pony .bat file MD5 hashes.
        bat_hashes = self.config.get('global', 'bat_hashes').split(',')
        bat_hashes = [h.lower() for h in bat_hashes]

        # These are observed Pony favicon.ico MD5 hashes.
        pony_favicon_hashes = self.config.get('global', 'favicon_hashes').split(',')
        pony_favicon_hashes = [h.lower() for h in pony_favicon_hashes]

        # Try to identify Pony by the .bat file that it drops.
        for bat_hash in bat_hashes:
            if bat_hash in [i['value'] for i in self.event_json['indicators'] if i['type'] == 'Hash - MD5']:
                self.detections.append('Detected Pony by the dropped .bat file hash: {}'.format(bat_hash))
                self.tags.append('pony')

        # Try to identify Pony by the favicon URL.
        for url in set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'URI - URL']):
            favicon_url = ''
            if 'gate.php' in url:
                favicon_url = url.replace('gate.php', 'includes/design/images/favicon.ico')
            if 'shit.exe' in url:
                favicon_url = url.replace('shit.exe', 'includes/design/images/favicon.ico')

            if favicon_url:
                try:
                    temp = tempfile.NamedTemporaryFile()
                    command = '{} -f {} wget -O {} -U {} -T {} {}'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, temp.name, shlex.quote(user_agent), 5, shlex.quote(favicon_url))
                    subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    with open(temp.name, 'rb') as image:
                        m = hashlib.md5()
                        m.update(image.read())
                        md5 = m.hexdigest().lower()
                        if md5.lower() in pony_favicon_hashes:
                            self.detections.append('Detected Pony by the favicon.ico associated with the URL: {}'.format(url))
                            self.tags.append('pony')
                        else:
                            self.detections.append('ERROR: Detected possible change in Pony favicon.ico: {}'.format(favicon_url))
                except:
                    self.logger.exception('Error downloading Pony favicon.ico: {}'.format(favicon_url))
