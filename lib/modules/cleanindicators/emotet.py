import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the Emotet cleanup module.')

    if 'emotet' in event_json['tags']:
        for i in event_json['indicators']:
            if i['type'] == 'URI - Path' or i['type'] == 'Email - Subject' or 'from_address' in i['tags'] or 'from_domain' in i['tags'] or i['type'] == 'Address - ipv4-addr' or i['type'] == 'Windows - FileName' or 'dropped_file' in i['tags']:
                logger.debug('Whitelisting "{}" Emotet indicator: {}'.format(i['type'], i['value']))
                i['whitelisted'] = True
