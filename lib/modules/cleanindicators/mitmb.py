import logging

logger = logging.getLogger()


def run(event_json):
    logger.debug('Running the MTIMB cleanup module.')

    if 'mitmb' in event_json['tags']:

        # Find the "from_domain" indicator.
        from_domain = ''
        for i in event_json['indicators']:
            if i['type'] == 'URI - Domain Name' and 'from_domain' in i['tags']:
                from_domain = i['value']

        # Check if the from_domain indicator is found inside any of the other domain indicators.
        if from_domain:
            for i in event_json['indicators']:
                if i['type'] == 'URI - Domain Name' and not from_domain == i['value'] and from_domain in i['value']:
                    logger.debug('Whitelisting MITMB indicator based on the from_domain {}: {}'.format(from_domain, i['value']))

                    # Whitelist any relationships as well.
                    for r in i['relationships']:
                        for ind in event_json['indicators']:
                            if ind['value'] == r:
                                logger.debug('Whitelisting MITMB indicator based on relationship to domain: {}'.format(r))
                                ind['whitelisted'] = True
