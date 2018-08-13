import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the Nanocore cleanup module.')

    if 'nanocore' in event_json['tags']:
        for i in event_json['indicators']:
            if i['type'] == 'Windows - File Name' and not 'sandboxed_sample' in i['tags']:
                logger.debug('Whitelisting "{}" Nanocore indicator: {}'.format(i['type'], i['value']))
                i['whitelisted'] = True
