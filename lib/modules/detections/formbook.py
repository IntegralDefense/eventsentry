import re

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        mutex1_pattern = re.compile(r'([a-z0-9]\-[a-z0-9]{14})', re.IGNORECASE)
        mutex2_pattern = re.compile(r'([a-z0-9]{16})', re.IGNORECASE)

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            mutex1 = ''
            mutex2 = ''

            # Loop over each mutex.
            for mutex in sample['mutexes']:

                # Split the mutex on \ and check each part.
                parts = mutex.split('\\')

                for part in parts:

                    # Check if the first mutex matches and that it contains letters and numbers.
                    matches = mutex1_pattern.findall(part)
                    for match in matches:
                        if any(c.isdigit() for c in match) and any(c.isalpha() for c in match):
                            mutex1 = mutex

                    # Check if the second mutex matches and that it contains letters and numbers.
                    matches = mutex2_pattern.findall(part)
                    for match in matches:
                        if any(c.isdigit() for c in match) and any(c.isalpha() for c in match):
                            mutex2 = mutex

            # Continue if both mutexes were found.
            if mutex1 and mutex2:
                self.detections.append('Detected Formbook malware by mutexes: {} AND {}'.format(mutex1, mutex2))
                self.tags.append('formbook')
