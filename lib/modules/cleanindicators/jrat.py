import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the jRAT cleanup module.')

    if 'jrat' in event_json['tags'] or 'adwind' in event_json['tags']:
        for i in event_json['indicators']:
            if not 'attachment' in i['tags'] and not 'sandboxed_sample' in i['tags']:
                if i['type'].startswith('Hash -') or i['type'] == 'Windows - FileName':
                    logger.debug('Whitelisting "{}" jRAT/Adwind indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
