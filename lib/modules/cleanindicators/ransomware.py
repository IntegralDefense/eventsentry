import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the ransomware cleanup module.')

    if 'ransomware' in event_json['tags']:
        for i in event_json['indicators']:
            if not 'attachment' in i['tags'] and not 'sandboxed_sample' in i['tags']:
                if i['type'].startswith('Hash -') or i['type'] == 'Windows - FileName':
                    logger.debug('Whitelisting "{}" ransomware indicator: {}'.format(i['type'], i['value']))
                    i['whitelisted'] = True
