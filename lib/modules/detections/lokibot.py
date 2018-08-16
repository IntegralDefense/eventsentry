import requests

from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))

        # Loop over each sandboxed sample in the event.
        for sample in self.event_json['sandbox']:

            # Loop over each HTTP request in the sample.
            for request in sample['http_requests']:

                # Make sure the request was to a known Loki Bot URI path.
                if request['uri'].endswith('/fre.php'):

                    # Continue if it was a POST request.
                    if request['method'] == 'POST':

                        # Detected Loki Bot if the user-agent matches.
                        if request['user_agent'] == 'Mozilla/4.08 (Charon; Inferno)':
                            self.detections.append('Detected Loki Bot by HTTP POST to URL "{}" with user-agent "{}"'.format(request['url'], request['user_agent']))
                            self.tags.append('lokibot')
                        else:
                            self.detections.append('ERROR: Looks like we detected Loki Bot, but a change in the user-agent: {}'.format(request['user_agent']))

                        # Get the HTTP status code from the request's URL. We are expecting a 404 response.
                        status_code = requests.head(request['url']).status_code
                        if status_code == 404:

                            # Get the text from the URL. We are expecting "File not found."
                            text = requests.get(request['url']).content.decode('utf-8').strip()
                            if text == 'File not found.':
                                self.detections.append('Detected Loki Bot by HTTP 404 response code and text at URL: {}'.format(request['url']))
                                self.tags.append('lokibot')
                            else:
                                self.detections.append('ERROR: Looks like we detected Loki Bot, but a change in the text at URL "{}" is now: {}'.format(request['url'], text))
                        else:
                            self.detections.append('ERROR: Looks like we detected Loki Bot, but a change in the HTTP status code at URL "{}" is now: {}'.format(request['url'], status_code))

