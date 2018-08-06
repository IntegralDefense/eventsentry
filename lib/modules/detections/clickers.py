import datetime
import logging
import subprocess

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the clickers detection module.')

    tags = []
    detections = []
    extra = []

    # These are the companies that will get Splunk queries.
    company_names = ['ashland', 'valvoline']

    # Get the start time.
    start_time = ''
    if event_json['emails']:
        start_time = event_json['emails'][0]['received_time']
    elif event_json['ace_alerts']:
        start_time = event_json['ace_alerts'][0]['time']

    # We need to make sure the start time is in the format "YYYY-MM-DD HH:MM:SS", which is 19 characters long.
    start_time = start_time[0:19]

    # These are legit things that we expect to generate some results.
    whitelisted_things = ['pcn0351378', 'pcn0351545', 'brians-macbook', 'A423312', 'A428055', 'A420539', 'A344816', 'A406794', 'A361144', 'A312391', 'A419591']
    whitelisted_things_string = ''
    for host in whitelisted_things:
        whitelisted_things_string += 'NOT {} '.format(host)
    whitelisted_things_string = whitelisted_things_string[:-1]

    # Only continue if we have a valid start time.
    if len(start_time) == 19:

        # Loop over each New/Analyzed URL in the event.
        unique_commands = []
        for i in [i for i in good_indicators if (i['type'] == 'URI - Domain Name' or i['type'] == 'Address - ipv4-addr') and (i['status'] == 'New' or i['status'] == 'Analyzed') and not 'from_domain' in i['tags']]:

            # Make a query for each company/Splunk source.
            for company in company_names:

                # This is the actual command line version of the Splunk query.
                command = 'http_proxy="" https_proxy="" /opt/splunklib/splunk.py --enviro {} -s "{}" "index=bluecoat OR index=bro_http OR index=carbonblack {} {}"'.format(company, start_time, i['value'], whitelisted_things_string)
                
                # This is the Splunk search displayed on the wiki.
                earliest_time = datetime.datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').strftime('%m/%d/%Y:%H:%M:%S')
                query = 'earliest={} index=bluecoat OR index=bro_http OR index=carbonblack {} {}'.format(earliest_time, i['value'], whitelisted_things_string)

                # Run this query if it is a new one.
                if not command in unique_commands:
                    unique_commands.append(command)

                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:

                            # Clean up the output lines.
                            cleaned_output_lines = []
                            for line in output.splitlines():

                                # Remove everything the first and last elements of the line. 
                                cleaned_output_lines.append(' '.join(line.split('"')[1:-1]))
                                 
                            extra.append('\n'.join(cleaned_output_lines))
                            detections.append('! POTENTIAL {} CLICKER ! {}'.format(company.upper(), i['value']))
                    except:
                        logger.exception('Error when running query: {}'.format(query))

    return tags, detections, extra
