from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Loop over all of the memory strings.
            for memory_string in sample['memory_strings']:

                if 'remcos v' in memory_string.lower():
                    self.detections.append('Detected Remcos by the memory string: {}'.format(memory_string))
                    self.tags.append('remcos')
