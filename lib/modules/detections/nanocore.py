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

                if 'nanocore' in memory_string.lower():
                    self.detections.append('Detected NanoCore by the memory string: {}'.format(memory_string))
                    self.tags.append('nanocore')

            # Loop over all of the process trees.
            trees = sample['process_trees'] + sample['process_trees_decoded']
            for tree in trees:
                tree = tree.lower()

                processes = ['DHCP Service', 'LAN Monitor', 'WAN Host', 'NAS Host']
                for process in processes:
                    if process.lower() in tree:
                        self.detections.append('Detected Nanocore by the process tree: {}'.format(process))
                        self.tags.append('nanocore')

