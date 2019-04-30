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
                
                if '|ddd|' in memory_string and 'beta' in memory_string and '1.0.' in memory_string and memory_string.count('|') == 13:
                    self.detections.append('Detected Loda by the memory string: {}'.format(memory_string))
                    self.tags.append('loda')
                    
