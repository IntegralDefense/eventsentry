import datetime
import logging
import re
import subprocess

logger = logging.getLogger()


def run(config, event_json, good_indicators):
    logger.debug('Running the clickers detection module.')

    tags = []
    detections = []
    extra = []

    # Identify the module's name.
    module_name = __name__.split('.')[-1]

    # Simple regex that defines what an employee ID looks like.
    employee_id_pattern = re.compile(r'{}'.format(config.get(module_name, 'employee_id_pattern')))

    """
    QUERY SPLUNK FOR CLICKERS IN PROXY LOGS
    """

    # These are the companies that will get Splunk queries.
    company_names = ['ashland', 'valvoline']

    # Store the employee IDs that clicked and need a follow up Duo search.
    duo_ids = {}
    for company in company_names:
        duo_ids[company] = []

    # Get the start time.
    start_time = ''
    if event_json['emails']:
        start_time = event_json['emails'][0]['received_time']
    elif event_json['ace_alerts']:
        start_time = event_json['ace_alerts'][0]['time']

    # We need to make sure the start time is in the format "YYYY-MM-DD HH:MM:SS", which is 19 characters long.
    start_time = start_time[0:19]

    # These are legit things that we expect to generate some results.
    whitelisted_things = list(set(config.get(module_name, 'whitelisted_things').split(',')))
    whitelisted_things_string = 'NOT ' + ' NOT '.join(whitelisted_things)

    # Only continue if we have a valid start time.
    if len(start_time) == 19:

        # Loop over each New/Analyzed URL in the event.
        unique_commands = []
        for i in [i for i in good_indicators if (i['type'] == 'URI - Domain Name' or i['type'] == 'Address - ipv4-addr') and (i['status'] == 'New' or i['status'] == 'Analyzed') and not 'from_domain' in i['tags']]:

            # Make a query for each company/Splunk source.
            for company in company_names:

                # Store the employee IDs who clicked for each domain/IP.
                clicker_ids = []

                # Store the Splunk output lines for each domain/IP.
                output_lines = []

                # This is the actual command line version of the Splunk query.
                command = 'http_proxy="" https_proxy="" /opt/splunklib/splunk.py --enviro {} -s "{}" "index=bluecoat OR index=bro_http OR index=carbonblack {} {}"'.format(company, start_time, i['value'], whitelisted_things_string)
                
                # Run this query if it is a new one.
                if not command in unique_commands:
                    unique_commands.append(command)

                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:

                            # Clean up the output lines.
                            for line in output.splitlines():

                                # Skip over the Bluecoat logs with authentication_failed since they don't identify a user.
                                if 'bluecoat' in line.lower() and 'authentication_failed' in line.lower():
                                    continue

                                # Remove everything the first and last elements of the line. 
                                cleaned_line = ' '.join(line.split('"')[1:-1])
                                output_lines.append(cleaned_line)

                                # Try to extract the user ID from the cleaned line, assuming it is a proxy log entry.
                                try:
                                    user_id = cleaned_line.split()[8]
                                    if employee_id_pattern.match(user_id):
                                        clicker_ids.append(user_id)
                                        tags.append('exploitation')
                                        tags.append('incidents')
                                except:
                                    pass

                                # Try to extract the user ID from the cleaned line, assuming it is a Carbon Black log entry.
                                try:
                                    user_id = cleaned_line.split()[88][-7:]
                                    if employee_id_pattern.match(user_id):
                                        clicker_ids.append(user_id)
                                        tags.append('exploitation')
                                        tags.append('incidents')
                                except:
                                    pass
                                    
                            extra.append('\n'.join(output_lines))
                    except:
                        logger.exception('Error when running Splunk search: {}'.format(command))

                """
                ANALYZE OUTPUT LINES FOR EACH CLICKER TO DETERMINE ACTION
                """

                # Dedup and standardize the format of the clicker IDs.
                clicker_ids = list(set([i.lower() for i in clicker_ids]))

                # Standardize the format of the output lines.
                output_lines = [line.lower() for line in output_lines]

                for user_id in clicker_ids:
                
                    # Get all of the Bluecoat log lines for this user.
                    bluecoat_lines = [line for line in output_lines if 'bluecoat' in line and user_id in line]

                    if bluecoat_lines:

                        # Determine the status of the click (i.e.: observed/denied).
                        if all(' denied ' in line for line in bluecoat_lines):
                            status = 'denied'
                        else:
                            status = 'observed'

                        # Determine the type of click (i.e.: http/https).
                        if all(' connect ' in line and ' 443 ' in line for line in bluecoat_lines):
                            click_type = 'https'
                        else:
                            click_type = 'http'

                        # Check if there were any POST requests (only works for http).
                        if any(' post ' in line for line in bluecoat_lines):
                            submitted = True
                        else:
                            submitted = False

                        # Add the appropriate event detections.
                        if submitted:
                            duo_ids[company].append(user_id)
                            detections.append('! CLICKER {} CREDENTIALS SUBMITTED ! {} {}'.format(company.upper(), user_id, i['value']))
                            tags.append('actionsonobjectives')
                            tags.append('exfil')
                        else:
                            detections.append('! CLICKER {} {} {} ! {} {}'.format(company.upper(), click_type.upper(), status.upper(), user_id, i['value']))

                        # Add the user ID to the Duo list if it was HTTPS+OBSERVED.
                        if status == 'observed' and click_type == 'https':
                            duo_ids[company].append(user_id)

                    # Get all of the Carbon Black log lines for this user.
                    carbonblack_lines = [line for line in output_lines if 'carbonblack' in line and user_id in line]

                    # Only bother adding an event detection for CB logs if there were no Bluecoat logs for this user.
                    if carbonblack_lines and not bluecoat_lines:
                        detections.append('! CLICKER {} OFF NETWORK ! {} {}'.format(company.upper(), user_id, i['value']))

                    # Make sure we actually added a detection for this user.
                    if not any(user_id in d for d in detections):
                        detections.append('! CLICKER {} STATUS UNKNOWN ! {} {}'.format(company.upper(), user_id, i['value']))

        """
        RUN ANY FOLLOW-UP DUO SEARCHES AS NECESSARY
        """

        if duo_ids and any(duo_ids[company] for company in duo_ids):

            # Make a query for each company/Splunk source.
            for company in duo_ids:

                # Make sure there are actually IDs in this company that we need to search for.
                if duo_ids[company]:

                    # Store the Splunk output lines for each Duo user.
                    output_lines = []

                    # Build the user ID "OR" string for the search.
                    user_id_string = ' OR '.join(list(set(duo_ids[company])))

                    # This is the actual command line version of the Splunk query.
                    command = 'http_proxy="" https_proxy="" /opt/splunklib/splunk.py --enviro {} -s "{}" "index=duo* {}"'.format(company, start_time, user_id_string)

                    try:
                        output = subprocess.check_output(command, shell=True).decode('utf-8')

                        # If there was output, it means the Splunk search returned something.
                        if output:

                            # Clean up the output lines.
                            for line in output.splitlines():

                                # Skip over the Bluecoat logs with authentication_failed since they don't identify a user.
                                if 'bluecoat' in line.lower() and 'authentication_failed' in line.lower():
                                    continue

                                # Remove everything the first and last elements of the line. 
                                cleaned_line = ' '.join(line.split('"')[1:-1])
                                output_lines.append(cleaned_line)

                            extra.append('\n'.join(output_lines))
                    except:
                        logger.exception('Error when running Splunk search: {}'.format(command)) 

                    """
                    ANALYZE OUTPUT LINES FOR EACH DUO USER TO DETERMINE DETECTIONS
                    """

                    # Standardize the format of the output lines.
                    output_lines = [line.lower() for line in output_lines]

                    for user_id in duo_ids[company]:

                        # Get all of the Duo log lines for this user.
                        duo_lines = [line for line in output_lines if user_id in line]

                        if duo_lines:
                            detections.append('! CLICKER {} DUO PUSH ! {}'.format(company.upper(), user_id))

    return tags, detections, extra
