import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the skmfeeds detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each e-mail in the event.
    for email in event_json['emails']:

        if 'skmfeeds' in email['headers'].lower():
            detections.append('Detected an skmfeeds e-mail by the headers: {}'.format(email['path']))
            tags.append('skmfeeds')

    return tags, detections, extra
