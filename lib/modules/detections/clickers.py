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
    ignore_these_companies = list(set(config.get(module_name, 'ignore_these_companies').split(',')))
    company_names = set()
    for alert in event_json['ace_alerts']:
        if alert['company_name'] and not alert['company_name'] in ignore_these_companies:
            company_names.add(alert['company_name'])

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
    if whitelisted_things:
        whitelisted_things_string = 'NOT ' + ' NOT '.join(whitelisted_things)
    else:
        whitelisted_things_string = ''

    # Get all of the New/Analyzed domains and IP addresses from the event.
    domains_ips = list(set([i['value'].lower() for i in good_indicators if (i['type'] == 'URI - Domain Name' or i['type'] == 'Address - ipv4-addr') and (i['status'] == 'New' or i['status'] == 'Analyzed') and not 'from_domain' in i['tags']]))
    if domains_ips:
        domains_ips_string = ' OR '.join(domains_ips)
    else:
        return tags, detections, extra

    # Only continue if we have a valid start time.
    if len(start_time) == 19:

        # Run the Splunk search for each company we found in the alerts.
        for company in company_names:

            """
            BUILD AND RUN THE SPLUNK SEARCH
            """

            # Store the employee IDs who clicked for each domain/IP.
            clicker_ids = []

            # Store the employee IDs who clicked and need a follow up Duo search.
            duo_ids = []

            # Store the Splunk output lines.
            output_lines = []

            # This is the actual command line version of the Splunk query.
            command = 'http_proxy="" https_proxy="" /opt/splunklib/splunk.py --enviro {} -s "{}" "index=bluecoat OR index=bro_http OR index=carbonblack NOT authentication_failed {} {}"'.format(company, start_time, domains_ips_string, whitelisted_things_string)
            
            try:
                output = subprocess.check_output(command, shell=True).decode('utf-8')

                # If there was output, it means the Splunk search returned something.
                if output:

                    # Clean up the output lines.
                    for line in output.splitlines():

                        # Replace the "s with spaces and remove the first and last elements of the line.
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

                    # Add the (cleaned) raw Splunk results to the extra text.                            
                    extra.append('\n'.join(output_lines))
            except:
                logger.exception('Error when running Splunk search: {}'.format(command))

            """
            ANALYZE SEARCH RESULTS TO DETERMINE TYPES OF CLICKERS
            """

            # Dedup and standardize the format of the clicker IDs.
            clicker_ids = list(set([i.lower() for i in clicker_ids]))

            # Standardize the format of the output lines.
            output_lines = [line.lower() for line in output_lines]

            # Loop over all of the domains and IPs we searched for to identify the clickers.
            for domain_ip in domains_ips:

                # Loop over each clicker to check if they clicked on this domain/IP.
                for user_id in clicker_ids:
                
                    # Get all of the Bluecoat log lines for this domain/IP + clicker.
                    bluecoat_lines = [line for line in output_lines if 'bluecoat' in line and domain_ip in line and user_id in line]

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

                        # Check if we need to add a message reminding us to lock the clicker's account.
                        # These are also the users we need to perform follow-up Duo searches for.
                        if submitted or (status == 'observed' and click_type == 'https'):
                            reminder_message = '<--- CONTACT USER AND LOCK ACCOUNT'
                            duo_ids.append(user_id)
                        else:
                            reminder_message = ''

                        # Add the appropriate event detections.
                        if submitted:
                            detections.append('! CLICKER {} CREDENTIALS SUBMITTED ! {} {} {}'.format(company.upper(), user_id, domain_ip, reminder_message))
                            tags.append('actionsonobjectives')
                            tags.append('exfil')
                        else:
                            detections.append('! CLICKER {} {} {} ! {} {} {}'.format(company.upper(), click_type.upper(), status.upper(), user_id, domain_ip, reminder_message))

                    # Get all of the Carbon Black log lines for this user.
                    carbonblack_lines = [line for line in output_lines if 'carbonblack' in line and domain_ip in line and user_id in line]

                    # Only bother adding an event detection for CB logs if there were no Bluecoat logs for this user.
                    if carbonblack_lines and not bluecoat_lines:
                        duo_ids.append(user_id)
                        detections.append('! CLICKER {} OFF NETWORK ! {} {} <--- CONTACT USER AND LOCK ACCOUNT'.format(company.upper(), user_id, domain_ip))

            # Make sure we actually added a detection for each user.
            for user_id in clicker_ids:
                if not any(user_id in d for d in detections):
                    detections.append('! CLICKER {} STATUS UNKNOWN ! {}'.format(company.upper(), user_id))

            """
            RUN ANY FOLLOW-UP DUO SEARCHES AS NECESSARY
            """

            if duo_ids:

                # Store the Splunk output lines.
                output_lines = []

                # Build the user ID "OR" string for the search.
                user_id_string = ' OR '.join(list(set(duo_ids)))

                # This is the actual command line version of the Splunk query.
                command = 'http_proxy="" https_proxy="" /opt/splunklib/splunk.py --enviro {} -s "{}" "index=duo* {}"'.format(company, start_time, user_id_string)

                try:
                    output = subprocess.check_output(command, shell=True).decode('utf-8')

                    # If there was output, it means the Splunk search returned something.
                    if output:

                        # Clean up the output lines.
                        for line in output.splitlines():

                            # Replace the "s with spaces and remove the first and last elements of the line.
                            cleaned_line = ' '.join(line.split('"')[1:-1])
                            output_lines.append(cleaned_line)

                        # Add the (cleaned) raw Splunk results to the extra text.
                        extra.append('\n'.join(output_lines))
                except:
                    logger.exception('Error when running Splunk search: {}'.format(command)) 

                """
                ANALYZE OUTPUT LINES FOR EACH DUO USER TO DETERMINE DETECTIONS
                """

                # Standardize the format of the output lines.
                output_lines = [line.lower() for line in output_lines]

                for user_id in duo_ids:

                    # Get all of the Duo log lines for this user.
                    duo_lines = [line for line in output_lines if user_id in line]

                    if duo_lines:
                        detections.append('! CLICKER {} DUO PUSH ! {}'.format(company.upper(), user_id))

    return tags, detections, extra
