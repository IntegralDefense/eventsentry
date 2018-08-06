import logging

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Wright Scott detection module.')

    tags = []
    detections = []
    extra = []

    # Loop over each e-mail address in the event.
    for email_address in [i['value'] for i in event_json['indicators'] if i['type'] == 'Email - Address']:

        if 'wrightscott' in email_address.lower():
            detections.append('Detected a Wright Scott e-mail address: {}'.format(email_address))
            tags.append('wrightscott')

    return tags, detections, extra
