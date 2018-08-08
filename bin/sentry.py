#!/usr/bin/env python3

import configparser
import logging, logging.handlers
import multiprocessing
import MySQLdb
import os
import signal
import subprocess
import sys
import time

"""
#
# INITIAL SETUP
#
"""

# Make sure the current directory is in the
# path so that we can run this from anywhere.
this_dir = os.path.join(os.path.dirname(__file__), '..')
if this_dir not in sys.path:
    sys.path.insert(0, this_dir)

from critsapi.critsdbapi import CRITsDBAPI
from critsapi.critsapi import CRITsAPI
from lib import indicator
from lib.constants import HOME_DIR
from lib.event import Event
from lib.confluence.ConfluenceEventPage import ConfluenceEventPage
from lib.intel import EventIntel

# Load the config file.
config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
if not os.path.exists(config_path):
    raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
config = configparser.ConfigParser()
config.read(config_path)

# Set up logging.
log_path = os.path.join(HOME_DIR, 'logs', 'eventsentry.log')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
filelog = logging.handlers.TimedRotatingFileHandler(log_path, when='midnight', interval=1, backupCount=6)
fileformatter = logging.Formatter('[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelname)s] - %(message)s')
filelog.setFormatter(fileformatter)
logger.addHandler(filelog)

# Set the NO_PROXY variable.
try:
    no_proxy_domains = config['production']['no_proxy_domains']
    os.environ['NO_PROXY'] = no_proxy_domains
    logger.debug('Setting NO_PROXY for: {}'.format(no_proxy_domains))
except:
    pass


"""
#
# EVENT FUNCTIONS
#
"""


def get_open_events():
    """ Query the ACE database to get the list of open events.
        Returns in the form of {'id': '1234', 'name': 'blah', 'alerts': []}
    """

    try:
        open_events = []

        # Connect to the database and get a cursor.
        db = MySQLdb.connect(host=config['production']['ace_db_server'], user=config['production']['ace_db_user'], passwd=config['production']['ace_db_pass'], db=config['production']['ace_db_name'])
        c = db.cursor()
        logger.debug('Connected to ACE database.')

        # Query the database for the open events.
        c.execute('SELECT * FROM events WHERE status="OPEN"')

        # Fetch the results and reformat the event names.
        rows = c.fetchall()
        for row in rows:
            _id = row[0]
            year = row[1].year
            month = str(row[1].month).zfill(2)
            day = str(row[1].day).zfill(2)
            name = str(row[2].replace(' ', '_'))
            event_name = '{}{}{}_{}'.format(year, month, day, name)
            open_events.append({'id': _id, 'name': event_name, 'alerts': []})

        # Loop over each open event and query the database for its alerts.
        for event in open_events:
            c.execute('SELECT * FROM event_mapping WHERE event_id="{}"'.format(event['id']))

            alert_ids = []

            # Fetch the results and get the alert IDs that are in this event.
            rows = c.fetchall()
            for row in rows:
                alert_ids.append(row[1])

            # Loop over each alert ID and get its storage path.
            for alert_id in alert_ids:
                c.execute('SELECT * FROM alerts WHERE id="{}"'.format(alert_id))

                # Fetch the results and get the storage path.
                rows = c.fetchall()
                for row in rows:
                    storage_path = row[3]
                    event['alerts'].append(storage_path)

        # Close the cursor and database connection.
        c.close()
        db.close()

        logger.info('There are {} open events.'.format(len(open_events)))

        return open_events
    except:
        logger.exception('Could not get open events from ACE!')
        return []


def process_event(event):
    """ Process the event. """

    logger.info('Starting to process event: {}'.format(event['name']))
    start_time = time.time()

    # Connect to the ACE database.
    ace_db = MySQLdb.connect(host=config['production']['ace_db_server'], user=config['production']['ace_db_user'], passwd=config['production']['ace_db_pass'], db=config['production']['ace_db_name'])

    # Create a CRITS Mongo connection.
    mongo_uri = config.get('production', 'crits_mongo_url')
    mongo_db = config.get('production', 'crits_mongo_db')
    logger.debug('Connecting to Mongo "{}" database: {}'.format(mongo_db, mongo_uri))
    mongo_connection = CRITsDBAPI(mongo_uri=mongo_uri, db_name=mongo_db)
    mongo_connection.connect()

    # Create a CRITS API connection.
    api_url = config.get('production', 'crits_api_url')
    cert = config.get('production', 'verify_requests_cert')
    api_key = config.get('production', 'crits_api_key')
    api_user = config.get('production', 'crits_api_user')
    logger.debug('Connecting to the CRITS API: {}'.format(api_url))
    crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=cert)

    # Get the valid campaigns from CRITS, excluding the "Campaign" campaign.
    crits_campaigns = list(mongo_connection.find_all('campaigns'))
    campaign_names = [c['name'] for c in crits_campaigns if not c['name'] == 'Campaign']

    # Store the CRITS campaign names with a lowercase wiki tag version.
    campaign_dict = {}
    for campaign in campaign_names:
        campaign_dict[campaign.replace(' ', '').lower()] = campaign

    # Create the event object.
    try:
        e = Event(event['id'], event['name'], mongo_connection)
    except:
        logger.exception('Error creating the Event object: {}'.format(event['name']))
        return

    # Build the event.json file.
    try:
        e.setup(alert_paths=event['alerts'])
    except:
        logger.exception('Error setting up the Event object: {}'.format(event['name']))
        return

    # Connect to the wiki page.
    wiki = ConfluenceEventPage(e.name_wiki, mongo_connection)

    # If the event has changed or we are forcing a refresh, we need to update the wiki page.
    if e.changed or wiki.is_page_refresh_checked():
        logger.info('Event has changed. Updating wiki: {}'.format(e.json['name']))

        """
        ADD ANY WHITELISTED INDICATORS FROM THE SUMMARY TABLE TO CRITS
        """

        # Read the Indicator Summary table to see if there are any checked (whitelisted) indicators.
        good_indicators, whitelisted_indicators = wiki.read_indicator_summary_table()

        if whitelisted_indicators:

            logger.info('Detected newly whitelisted indicators: {}'.format(e.json['name']))

            # If there were any Hash indicators checked as whitelisted, we need to check if there are any related
            # Hash indicators that were NOT checked. If there were, we want to make sure to treat them as whitelisted.
            hash_cache = []
            for i in whitelisted_indicators:
                if i['type'].startswith('Hash - '):

                    # Loop over the indicators in the event JSON to find the matching indicator.
                    for json_indicator in e.json['indicators']:
                        if i['type'] == json_indicator['type'] and i['value'] == json_indicator['value']:

                            # Loop over the relationships (the corresponding hashes) and see if any of them
                            # are in the good indicators list (as in they were not checked as whitelisted on the wiki).
                            relationships = json_indicator['relationships']
                            for rel in relationships:

                                # Only continue if we haven't already verified this hash.
                                if not rel in hash_cache:
                                    hash_cache.append(rel)
                                    for good_indicator in good_indicators:
                                        if good_indicator['type'].startswith('Hash - ') and good_indicator['value'] == rel:

                                            # Add the good hash indicator to the whitelisted indicator list.
                                            logger.debug('Whitelisting "{}" indicator "{}" by association to: {}'.format(good_indicator['type'], rel, i['value']))
                                            whitelisted_indicators.append(good_indicator)

            # Add the whitelisted indicators to the CRITS whitelist.
            for i in whitelisted_indicators:
                # If this is a "URI - Path" or "URI - URL" indicator, check its relationships to see if its
                # corresponding "URI - Domain Name" or "Address - ipv4-addr" indicator was also checked. If it was,
                # we want to ignore the path and URL indicators since the domain/IP serves as a least common denominator.
                # This prevents the CRITS whitelist from ballooning in size and slowing things down over time.
                skip = False
                if i['type'] == 'URI - Path' or i['type'] == 'URI - URL':

                    # Loop over the indicators in the event JSON to find the matching indicator.
                    for json_indicator in e.json['indicators']:
                        if i['type'] == json_indicator['type'] and i['value'] == json_indicator['value']:

                            # Loop over the whitelisted indicators and see any of them are a whitelisted (checked)
                            # domain name or IP address. If the domain/IP appears in the relationships (for the
                            # "URI - Path" indicators) or in the value (for "URI - URL" indicators), we can ignore it.
                            relationships = json_indicator['relationships']
                            for x in whitelisted_indicators:
                                if x['type'] == 'URI - Domain Name' or x['type'] == 'Address - ipv4-addr':
                                    if any(x['value'] in rel for rel in relationships) or x['value'] in i['value']:
                                        logger.debug('Ignoring redundant "{}" indicator "{}" for CRITS whitelist.'.format(i['type'], i['value']))
                                        skip = True

                if not skip:
                    logger.warning('Adding "{}" indicator "{}" to CRITS whitelist.'.format(i['type'], i['value']))
    
                    try:
                        result = crits_api.add_indicator(i['value'], i['type'], source='Integral',
                                                         reference=wiki.get_page_url(), bucket_list=['whitelist:e2w'],
                                                         add_domain=False)
    
                        # If the indicator was added successfully, update its status to Deprecated.
                        if result:
                            crits_api.status_update(result['id'], result['type'], 'Deprecated')
                    except:
                        logger.exception('Error adding "{}" indicator "{}" to CRITS whitelist'.format(i['type'], i['value']))

        """
        PULL IN MANUAL INDICATORS FROM THE WIKI PAGE INTO THE EVENT JSON
        """

        # Read whatever manual indicators are listed on the wiki page.
        manual_indicators = wiki.read_manual_indicators()
        if manual_indicators:

            # Add a "manual_indicator" tag to the indicators so that we can exclude them from the
            # monthly indicator pruning process.
            for i in manual_indicators:
                i['tags'].append('manual_indicator')

            logger.info('Adding new manual indicators to CRITs: {}'.format(e.json['name']))

        # Check if any of the indicators in the event JSON have the 'manual_indicator' tag.
        # Since there aren't any indicators in the Manual Indicators section, this indicates
        # that they were deleted from the page.
        else:
            if any('manual_indicator' in ind['tags'] for ind in e.json['indicators']):
                logger.info('Manual indicators removed from wiki. Need to remove them from CRITs: {}'.format(e.json['name']))

        """
        RE-SETUP THE EVENT
        """

        # Parse the event.
        try:
            e.setup(manual_indicators=manual_indicators, force=True)
        except:
            logger.exception('Error refreshing Event object: {}'.format(e.json['name']))
            return

        # Get the remediation status for the e-mails in the event.
        try:
            for email in e.json['emails']:
                email['remediated'] = False

                if email['original_recipient']:
                    key = '{}:{}'.format(email['message_id'], email['original_recipient'])
                elif len(email['to_addresses']) == 1:
                    key = '{}:{}'.format(email['message_id'], email['to_addresses'][0])

                # Continue if we were able to create the MySQL "key" value for this e-mail.
                if key:

                    # Search the ACE database for the remediation status.
                    c = ace_db.cursor()
                    query = 'SELECT * FROM remediation WHERE `key`="{}"'.format(key)
                    c.execute(query)

                    # Fetch all of the rows.
                    rows = c.fetchall()
                    for row in rows:
                        result = row[6]
                        # A successful result string in the database looks like:
                        # (200) [{"address":"recipientuser@domain.com","code":200,"message":"success"}]
                        if '"code":200' in result and '"message":"success"' in result:
                            email['remediated'] = True
        except:
            logger.exception('Error getting remediation status for e-mail.')
                        
        """
        ADD CRITS STATUS OF EACH INDICATOR TO THE EVENT JSON
        """

        # Used as a cache so we don't query CRITS for the same indicator.
        queried_indicators = {}

        # Query CRITS to get the status of the indicators.
        logger.debug('Querying CRITS for indicator statuses.') 

        for i in e.json['indicators']:
            type_value = '{}{}'.format(i['type'], i['value'])

            # Continue if we haven't already processed this type/value pair indicator.
            if not type_value in queried_indicators:

                # Get the indicator status from CRITS. Ignore any indicators that were already set to Informational.
                if not i['status'] == 'Informational':
                    i['status'] = indicator.get_crits_status(mongo_connection, i)

                # Add the indicator to the queried cache.
                queried_indicators[type_value] = i['status']
            # We've already queried CRITS for this type/value, so just set the status.
            else:
                i['status'] = queried_indicators[type_value]

        """
        RUN ALL OF THE EVENT DETECTION MODULES
        """

        good_indicators = [ind for ind in e.json['indicators'] if not ind['whitelisted']]
        e.event_detections(good_indicators)

        """
        RUN ALL OF THE CLEAN INDICATOR MODULES
        """

        e.clean_indicators()

        """
        GATHER UP ALL OF THE EVENT TAGS
        """
     
        # Add the wiki tags to the event tags. This ensures that tags that we add to the wiki page
        # get added to the indicators in the Indicator Summary table.
        e.json['tags'] += wiki.get_labels()
        e.json['tags'] = list(set(e.json['tags']))

        # Check if the event tags have a campaign name in them.
        if 'campaign' in e.json['tags']:
            # See if any of the event tags are a valid campaign name.
            for tag in e.json['tags']:
                if tag in campaign_dict:
                    # Set the campaign name in the event JSON.
                    e.json['campaign'] = {'crits': campaign_dict[tag], 'wiki': tag}

        # Replace any campaign tag with the "apt:" version.
        try:
            e.json['tags'].append('apt:{}'.format(e.json['campaign']['wiki']))
            e.json['tags'].remove(e.json['campaign']['wiki'])
        except:
            pass

        """
        UPDATE THE WIKI PAGE
        """

        # Refresh the wiki page using the updated JSON.
        try:
            wiki.refresh_event_page(e.json)
        except:
            logger.exception('Error refreshing wiki page: {}'.format(e.json['name']))

        # Since we updated the wiki page, add the version to the event JSON. This is used
        # so that the intel processing button can not process a wiki page that has a newer
        # version without first refreshing the page.
        e.json['wiki_version'] = wiki.get_page_version()

        """
        PROCESS THE EVENT INTEL
        """

        # Make the .crits intel directory structure and write the indicators.
        good_indicators, whitelisted_indicators = wiki.read_indicator_summary_table()

        event_intel = EventIntel(e.json, good_indicators)
        event_intel.build_symlink_directory_structure()
        event_intel.place_indicator_and_relationship_csvs()

        # Write out the event JSON.
        e.write_json()

    # If the intel processing checkbox is checked...
    if wiki.is_event_ready_for_crits_processing(e.json['wiki_version']):
        logger.info('Processing the event intel: {}'.format(e.json['name']))

        # Figure out the event source.
        wiki_labels = wiki.get_labels()
        if 'valvoline' in wiki_labels:
            source = 'Valvoline'
        elif 'ashland' in wiki_labels:
            source = 'Ashland'
        else:
            source = 'Integral'

        # Try to get the event description from the Overview section.
        overview_section = wiki.get_section('overview')
        try:
            description = overview_section.find('p').text
        except:
            description = ''

        if source and description :
            commands = []

            # CD into the intel directory.
            crits_root = os.path.join(e.json['path'], '.crits')
            cd_command = 'cd {}'.format(crits_root)
            commands.append(cd_command)

            # Command to remove any bad characters from the intel files.
            sed_command = 'find {} -type f -exec sed -i "s/\\x0//g" {{}} \;'.format(crits_root)
            commands.append(sed_command)

            # Get the event campaign.
            try:
                campaign = e.json['campaign']['crits']
                campaign_conf = 'medium'
            except:
                campaign = ''
                campaign_conf = ''

            # Figure out the event type.
            if e.json['emails']:
                event_type = 'Phishing'
            else:
                event_type = 'Malicious Code'

            # Figure out the event time.
            if e.json['emails']:
                event_time = e.json['emails'][0]['received_time']
            else:
                event_time = e.json['ace_alerts'][0]['time']

            # Strip out any timezone offset if the event time has one.
            # 2018-05-16 07:56:09
            if len(event_time) > 19:
                event_time = event_time[0:19]

            # Build the getitintocrits.py command.
            giic_command = 'getitintocrits.py --no-prompt -s "{}" -r "{}" -e "{}" --description "{}" --type "{}" --date "{}" --campaign "{}" --campaign-conf "{}" --bucket-list "{}"'.format(
                source, wiki.get_page_url(), e.json['name'], description, event_type, event_time, campaign,
                campaign_conf, ','.join(sorted(list(set(e.json['tags'])))))
            commands.append(giic_command)

            # Command to craft the relationships between all the indicators and objects.
            br_command = 'build_relationships.py {}'.format(os.path.join(crits_root, 'relationships.txt'))
            commands.append(br_command)

            # Continue if we have the required pieces to run getitintocrits.py.
            if description and event_type and event_time and e.json['tags']:
                # Run all of the commands.
                command_string = ' && '.join(commands)
                os.system(command_string)
                
                # Query CRITS to make sure the event actually exists now.
                crits_events = [e['title'] for e in list(mongo_connection.find_all('events'))]
                if e.json['name'] in crits_events:

                    # If it exists in CRITS, close the event in ACE.
                    try:
                        c = ace_db.cursor()
                        c.execute('SELECT * FROM events WHERE status="OPEN" AND id={}'.format(e.json['ace_id']))
                        if c.fetchone():
                            c.execute('UPDATE events SET status="CLOSED" WHERE id={}'.format(e.json['ace_id']))
                            ace_db.commit()
                            logger.warning('Closed event in ACE: {}'.format(e.json['name']))
                        c.close()

                        # Update the wiki to reflect that the event was processed into CRITS.
                        wiki.update_event_processed()
                    except:
                        logger.exception('Error when closing the event in ACE: {}'.format(e.json['name']))

    # Close the ACE database connection.
    ace_db.close()

    logger.info('Finished event "{0:s}" in {1:.5f} seconds.'.format(event['name'], time.time() - start_time))


"""
#
# SENTRY FUNCTIONS
#
"""


def start(num_workers=1):
    """ Initializes a process pool and indefinitely queries ACE for open events to process. """

    def signal_handler(signum, frame):
        """ Signal handler so the process pool can complete gracefully. """

        logger.warning('Caught signal to terminate! Waiting for pool to finish processing.')
        pool.close()
        pool.join()
        logger.warning('Goodbye.')
        sys.exit()

    def init_worker():
        """ Ignore SIGINT within the worker processes so
        that they can finish their work before exiting. """

        signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Register the signal handler for SIGINT.
    signal.signal(signal.SIGINT, signal_handler)

    # Make sure we don't create too many processes.
    if num_workers > os.cpu_count():
        num_workers = os.cpu_count()

    # Make sure we create at least one process.
    if num_workers < 1:
        num_workers = 1

    logger.info('Starting Event Sentry with {} workers.'.format(num_workers))

    try:
        while True:
            start_time = time.time()

            # Get the list of open events.
            open_events = get_open_events()

            # Create the process pool.
            pool = multiprocessing.Pool(processes=num_workers, initializer=init_worker)

            # Build the list of argument tuples for starmap.
            argument_tuples = []
            for event in open_events:
                argument_tuples.append((event,))

            # Map the work queue (list of open events) into the pool.
            pool.starmap(process_event, argument_tuples)

            # Close the pool so no more tasks can be added to it.
            pool.close()

            # Wait for the worker processes to finish work
            pool.join()

            logger.info('Time taken = {0:.5f}'.format(time.time() - start_time))

            # Wait a little while before starting over.
            time.sleep(3)
    except:
        logger.exception('Caught an exception while running the sentry.')
        pool.close()
        pool.terminate()
        sys.exit()


if __name__ == '__main__':
    start(num_workers=2)
