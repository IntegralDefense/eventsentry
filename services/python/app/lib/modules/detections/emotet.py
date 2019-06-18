import re

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Try to identify Emotet by the e-mail format.
        for email in self.event_json['emails']:
            if len(email['to_addresses']) == 1 and email['to_addresses'][0]:
                try:
                    to_domain = email['to_addresses'][0].split('@')[1].lower()

                    message_id_pattern_v1v2 = re.compile(r'[0-9]{5,}\.201[7-9][0-9]{5,}@' + to_domain)
                    if message_id_pattern_v1v2.search(email['message_id'].lower()):
                        if email['urls'] and not email['attachments']:
                            self.detections.append('Detected Emotet v1/v2 by the message-id and e-mail format: {}'.format(email['message_id']))
                            self.tags.append('emotet')

                    message_id_pattern_v3 = re.compile(r'[0-9]{18,21}.[0-9a-z]{16}@' + to_domain)
                    if message_id_pattern_v3.search(email['message_id'].lower()):
                        if email['urls'] and not email['attachments']:
                            self.detections.append('Detected Emotet v3 by the message-id and e-mail format: {}'.format(email['message_id']))
                            self.tags.append('emotet')
                except IndexError:
                    pass

        # Try to identify Emotet "v2" by sandbox results.
        for sample in self.event_json['sandbox']:
            trees = sample['process_trees'] + sample['process_trees_decoded']
            for tree in trees:
                tree = tree.lower()
                process = 'packiwamreg.exe'
                if process in tree:
                    self.detections.append('Detected Emotet v2 by the process tree: {}'.format(process))
                    self.tags.append('emotet')

        # Try to identify Emotet "v1" by sandbox results.
        exe_pattern = re.compile(r'(\d+\.exe)')
        for sample in self.event_json['sandbox']:
            trees = sample['process_trees'] + sample['process_trees_decoded']
            for tree in trees:
                tree = tree.lower()
                exe_match = None
                exe_matches = exe_pattern.findall(tree)
                for exe in exe_matches:
                    if exe_matches.count(exe) == 2:
                        exe_match = exe

                if exe_match:
                    process_match = False
                    if tree.find('winword') < tree.find('cmd') < tree.find('powershell') < tree.find(exe_match):
                        process_match = True

                    if exe_match and process_match:
                        if any(request['method'] == 'POST' for request in sample['http_requests']):
                            self.detections.append('Detected Emotet v1 by the HTTP POSTs, process tree, and .exe: {}'.format(exe_match))
                            self.tags.append('emotet')
                        else:
                            self.logger.warning('Looks like we detected Emotet, but there are no HTTP POST requests.')
                    else:
                        self.logger.warning('Detected possible Emotet .exe "{}", but process tree did not match.'.format(exe_match))

