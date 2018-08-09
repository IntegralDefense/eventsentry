import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the short URI path cleanup module.')

    for i in event_json['indicators']:
        # Remove any URI path indicators if the path is what we consider to be too short. Skip any manual indicators.
        if i['type'] == 'URI - Path' and len(i['value']) < 12 and not 'manual_indicator' in i['tags']:
            logger.debug('Whitelisting URI path indicator due to length: {}'.format(i['value']))
            i['whitelisted'] = True
