import logging
import subprocess

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the Fuzzy detection module.')

    tags = []
    detections = []
    extra = []

    # Try to detect Fuzzy by a Nigerian hunt ACE alert.
    for ace_alert in event_json['ace_alerts']:
        if 'Email Nigeria Originating' in ace_alert['description']:
            detections.append('Detected Nigerian (Fuzzy) by ACE alert: {}'.format(ace_alert['description']))
            tags.append('campaign')
            tags.append('fuzzy')

    # Try to detect Fuzzy by the IP geolocation.
    for ip in set([i['value'] for i in event_json['indicators'] if i['type'] == 'Address - ipv4-addr' and not i['whitelisted']]):

        # Perform the geoiplookup command.
        try:
            output = subprocess.check_output(['geoiplookup', ip]).decode('utf-8')
            if 'nigeria' in output.lower():
                detections.append('Detected Nigerian (Fuzzy) IP address by geolocation: {}'.format(ip))
                tags.append('campaign')
                tags.append('fuzzy')
        except:
            logger.exception('Could not geolocate IP address: {}'.format(ip))

    # Try to detect Fuzzy by WHOIS information.
    for whois in event_json['whois']:
        if 'country: ng' in whois['raw'].lower() or 'country: nigeria' in whois['raw'].lower():
            extra.append(whois['raw'])
            detections.append('Detected Nigerian (Fuzzy) domain by WHOIS: {}'.format(whois['domain']))
            tags.append('campaign')
            tags.append('fuzzy')

    return tags, detections, extra
