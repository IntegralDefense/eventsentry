import logging

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the Exec Spoof detection module.')

    tags = []
    detections = []
    extra = []

    for alert in event_json['ace_alerts']:
        if 'Phish Spoof ' in alert['description'] and ' Exec ' in alert['description']:
            detections.append('Detected an exec spoof phish: {}'.format(alert['description']))
            tags.append('bec')
            tags.append('exec_spoof')

    return tags, detections, extra
