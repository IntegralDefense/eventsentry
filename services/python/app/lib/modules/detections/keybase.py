from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Loop over all of the process trees.
            trees = sample['process_trees'] + sample['process_trees_decoded']
            for tree in trees:
                tree = tree.lower()

                strings = ['C:\\ProgramData\\Mails.txt', 'C:\\ProgramData\\Browsers.txt']
                if all(string.lower() in tree for string in strings):
                    self.detections.append('Detected KeyBase by the process tree: {}'.format(' AND '.join(strings)))
                    self.tags.append('keybase')

