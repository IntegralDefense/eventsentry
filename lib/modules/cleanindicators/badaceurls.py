import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the bad ACE URL cleanup module.')

    for i in event_json['indicators']:
        # Remove any URL and URI path indicators if they are bad URLs from ACE with double quotes.
        if (i['type'] == 'URI - URL' or i['type'] == 'URI - Path') and (i['value'].count('"') == 2 or i['value'].count("'") == 2):
            logger.debug('Whitelisting URL indicator due to ACE double quote bug: {}'.format(i['value']))
            i['whitelisted'] = True
