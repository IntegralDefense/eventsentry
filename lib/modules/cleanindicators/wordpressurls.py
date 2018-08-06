import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the Wordpress URL cleanup module.')

    for i in event_json['indicators']:
        if i['type'] == 'URI - URL' or i['type'] == 'URI - Path':
            
            # Make sure this is a Wordpress URL or path with .js in it.
            if ('wp-content' in i['value'] or 'wp-includes' in i['value']) and '.js' in i['value']:
                logger.debug('Whitelisting Wordpress .js indicator: {}'.format(i['value']))
                i['whitelisted'] = True
