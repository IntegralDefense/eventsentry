import re

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each sandboxed sample in the event.
        dropped_path_regex = re.compile(r'\\[a-zA-Z]{11}\\ID\.txt')
        for sample in self.event_json['sandbox']:
            dropped_name = ''
            dropped_path = ''
            for dropped in sample['dropped_files']:
                if dropped['filename'].startswith('Retrive') and dropped['filename'].endswith('.vbs'):
                    dropped_name = dropped['filename']
                if dropped['filename'] == 'ID.txt':
                    if dropped_path_regex.search(dropped['path']):
                        dropped_path = dropped['path']
            if dropped_name and dropped_path:
                self.detections.append('Detected jRAT/Adwind by the dropped file "{}" and dropped path "{}"'.format(dropped_name, dropped_path))
                self.tags.append('jrat')
                self.tags.append('adwind')
            elif dropped_name and not dropped_path:
                self.detections.append('ERROR: Looks like we detected jRAT/Adwind by the dropped file "{}" but did not find ID.txt dropped file path'.format(dropped_name))
            elif dropped_path and not dropped_name:
                self.detections.append('ERROR: Looks like we detected jRAT/Adwind by the dropped path "{}" but did not find Retrive vbs file'.format(dropped_path))

