import hashlib
import logging
import requests

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the Pony detection module.')

    tags = []
    detections = []
    extra = []

    # Try to identify Pony by the .bat file that it drops.
    bat_hash = '3880eeb1c736d853eb13b44898b718ab'
    if bat_hash in [i['value'] for i in event_json['indicators'] if i['type'] == 'Hash - MD5']:
        detections.append('Detected Pony by the dropped .bat file hash: {}'.format(bat_hash))
        tags.append('pony')

    # Try to identify Pony by the favicon URL.
    for url in set([i['value'] for i in event_json['indicators'] if i['type'] == 'URI - URL']):
        favicon_url = ''
        if 'gate.php' in url:
            favicon_url = url.replace('gate.php', 'includes/design/images/favicon.ico')
        if 'shit.exe' in url:
            favicon_url = url.replace('shit.exe', 'includes/design/images/favicon.ico')

        if favicon_url and requests.head(favicon_url):
            favicon = requests.get(favicon_url).content
            m = hashlib.md5()
            m.update(favicon)
            favicon_md5 = m.hexdigest()
            if favicon_md5 == 'b2e87bb6f28663fe5d28dec0d980d4cb':
                detections.append('Detected Pony by the favicon associated with the URL: {}'.format(url))
                tags.append('pony')
            else:
                detections.append('ERROR: Detected possible change in Pony favicon.ico: {}'.format(favicon_url))

    return tags, detections, extra
