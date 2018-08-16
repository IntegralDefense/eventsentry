from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each unique URL in the event.
        for url in set([i['value'] for i in self.event_json['indicators'] if i['type'] == 'URI - URL']):

            ss = ['/mlu/forum.php', '/d2/about.php', '/ls5/forum.php', '/4/forum.php']
            for s in ss:
                if s.lower() in url.lower():
                    self.detections.append('Detected Hancitor by the URI path "{}": {}'.format(s, url))
                    self.tags.append('hancitor')

