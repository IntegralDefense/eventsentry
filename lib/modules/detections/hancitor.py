import logging

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the Hancitor detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each unique URL in the event.
    for url in set([i['value'] for i in event_json['indicators'] if i['type'] == 'URI - URL']):

        ss = ['/mlu/forum.php', '/d2/about.php', '/ls5/forum.php']
        for s in ss:
            if s.lower() in url.lower():
                detections.append('Detected Hancitor by the URI path "{}": {}'.format(s, url))
                tags.append('hancitor')

    return tags, detections, extra
