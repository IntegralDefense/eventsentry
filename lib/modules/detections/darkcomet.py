from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Loop over all of the mutexes.
            for mutex in sample['mutexes']:
                s = 'DC_MUTEX-'
                if s.lower() in mutex.lower():
                    self.detections.append('Detected Dark Comet by the mutex: {}'.format(mutex))
                    self.tags.append('darkcomet')

