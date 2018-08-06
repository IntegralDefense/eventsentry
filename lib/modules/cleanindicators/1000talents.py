import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the 1000 Talents cleanup module.')

    if '1000_talents' in event_json['tags'] or '1000 talents' in event_json['tags'] or any('1000 talents' in a['tags'] for a in event_json['ace_alerts']) or any('1000_talents' in a['tags'] for a in event_json['ace_alerts']):
        for i in event_json['indicators']:
            if i['type'].startswith('URI -'):
                logger.debug('Whitelisting "{}" 1000 Talents indicator: {}'.format(i['type'], i['value']))
                i['whitelisted'] = True
