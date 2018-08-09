import logging

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the Morning Please detection module.')

    tags = []
    detections = []
    extra = []

    # Identify the module's name.
    module_name = __name__.split('.')[-1]

    # Get the list of e-mail addresses from the config.
    mp_emails = config.get(module_name, 'emails').split(',')

    # Try to identify Morning Please by the e-mail body.
    for email in event_json['emails']:

        # Make sure there is a Word document attachment.
        if any('.doc' in attach['name'].lower() for attach in email['attachments']):

            # These are the possible Morning Please string combinations.
            string_combos = []
            string_combos.append(['Morning,', 'Attached'])
            string_combos.append(['Morning,', 'Please see attached.'])
            string_combos.append(['Morning,', 'Please see attached and confirm.'])

            for ss in string_combos:
                if all(s in email['body'] for s in ss):
                    detections.append('Detected a Morning Please phish by Word document attachment and the e-mail body: {}'.format(ss))
                    tags.append('morningplease')
                elif all(s in email['html'] for s in ss):
                    detections.append('Detected a Morning Please phish by Word document attachment and the e-mail body: {}'.format(ss))
                    tags.append('morningplease')

    for whois in event_json['whois']:
        for mp_email in mp_emails:
            if mp_email.lower() in whois['raw'].lower():
                extra.append(whois['raw'])
                detections.append('Detected a Morning Please domain "{}" by WHOIS e-mail: {}'.format(whois['domain'], mp_email))
                tags.append('morningplease')

    return tags, detections, extra
