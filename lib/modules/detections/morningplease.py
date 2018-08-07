import logging

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the Morning Please detection module.')

    tags = []
    detections = []
    extra = []

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

    # Try to identify Morning Please by WHOIS.
    mp_emails = ['jichang@yahoo.com', 'WilliamKCrum@yahoo.com', 'jiamcho1955@dnsname.info', 'opicasts@dnsname.info',
                 'LiliKung@rhyta.com', 'shingtao@jourrapide.com', 'zhejiangshangbang@qq.com']

    for whois in event_json['whois']:
        for mp_email in mp_emails:
            if mp_email.lower() in whois['raw'].lower():
                extra.append(whois['raw'])
                detections.append('Detected a Morning Please domain "{}" by WHOIS e-mail: {}'.format(whois['domain'], mp_email))
                tags.append('morningplease')

    return tags, detections, extra
