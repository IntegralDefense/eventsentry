#!/usr/local/bin/pypy3

import datetime
import logging, logging.handlers
import multiprocessing
import os
import requests
import signal
import subprocess
import sys
import time
import urllib.parse

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
from lib.ace import ace_api
from lib.config import config
from lib.constants import HOME_DIR, GETITINTOCRITS, BUILD_RELATIONSHIPS
from lib.event import Event
from lib.confluence.ConfluenceEventPage import ConfluenceEventPage
from lib.intel import EventIntel
from pysip import Client, ConflictError

# Set up logging.
logging.basicConfig(format='%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s', level=logging.INFO)
welcome = """
███████╗██╗   ██╗███████╗███╗   ██╗████████╗    ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
█████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║       ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝
    """
logging.info(welcome)

# Set the NO_PROXY variable.
try:
    no_proxy_domains = config['network']['no_proxy_domains']
    os.environ['NO_PROXY'] = ','.join(no_proxy_domains)
    logging.info('Setting NO_PROXY for: {}'.format(no_proxy_domains))
except:
    pass

# Create a SIP connection.
if config['intel']['sip']['enabled']:
    if config['network']['verify_requests']:
        if os.path.exists('/certificate'):
            sip_verify = '/certificate'
        else:
            sip_verify = True
    else:
        sip_verify = False
    sip_host = config['intel']['sip']['sip_host']
    sip_apikey = config['intel']['sip']['sip_apikey']
    sip = Client(sip_host, sip_apikey, verify=sip_verify)
    logging.debug('Connected to SIP: {}'.format(sip_host))
else:
    sip = False


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
        open_events = ace_api.get_open_events()
        num_open_events = len(open_events)
        if num_open_events == 1:
            logging.info('There is {} open event.'.format(num_open_events))
        else:
            logging.info('There are {} open events.'.format(len(open_events)))

        return open_events
    except requests.exceptions.ConnectionError:
        logging.exception('Could not get open events from ACE!')
        return []

def process_event(event, sip_campaign_names):
    """ Process the event. """

    logging.info('Starting to process event: {}'.format(event['name']))
    start_time = time.time()

    # Create a CRITs Mongo connection.
    if config['intel']['crits']['enabled']:
        mongo_uri = config['intel']['crits']['crits_mongo_url']
        mongo_db = config['intel']['crits']['crits_mongo_db']
        mongo_connection = CRITsDBAPI(mongo_uri=mongo_uri, db_name=mongo_db)
        mongo_connection.connect()
        logging.debug('Connected to CRITS Mongo database: {}@{}'.format(mongo_db, mongo_uri))
    else:
        mongo_connection = False
    
    # Create a CRITs API connection.
    if config['intel']['crits']['enabled']:
        if config['network']['verify_requests']:
            if os.path.exists('/certificate'):
                crits_verify = '/certificate'
            else:
                crits_verify = True
        else:
            crits_verify = False
        api_url = config['intel']['crits']['crits_api_url']
        api_key = config['intel']['crits']['crits_api_key']
        api_user = config['intel']['crits']['crits_api_user']
        crits_api = CRITsAPI(api_url=api_url, api_key=api_key, username=api_user, verify=crits_verify)
        logging.debug('Connected to the CRITs API: {}'.format(api_url))
    else:
        crits_api = False

    # Get the valid campaigns from CRITs, excluding the "Campaign" campaign.
    if mongo_connection:
        crits_campaigns = list(mongo_connection.find_all('campaigns'))
        campaign_names = [c['name'] for c in crits_campaigns if not c['name'] == 'Campaign']
    else:
        campaign_names = []

    # Store the CRITs campaign names with a lowercase wiki tag version.
    campaign_dict = dict()
    for campaign in campaign_names:
        campaign_dict[campaign.replace(' ', '').lower()] = campaign

    # Create the event object.
    try:
        e = Event(event, mongo_connection, sip)
    except:
        logging.exception('Error creating the Event object: {}'.format(event['name']))
        return

    # Build the event.json file.
    try:
        e.setup(alert_uuids=event['alerts'])
    except:
        logging.exception('Error setting up the Event object: {}'.format(event['name']))
        return

    # Connect to the wiki page.
    wiki = ConfluenceEventPage(e.name_wiki, mongo_connection)
    
    # Add the wiki page URL to the event JSON.
    e.json['wiki_url'] = wiki.get_page_url()

    # If the event has changed or we are forcing a refresh, we need to update the wiki page.
    if e.changed or wiki.is_page_refresh_checked():

        # 99% of the same things need to be updated if the event has changed or if someone
        # forced a refresh using the wiki page. However, there are a couple differences between
        # the two, so if the event has changed somehow, we want to make sure that takes
        # precedence over the wiki refresh button.
        if e.changed:
            wiki_refresh = False
            logging.info('Event has changed. Updating wiki: {}'.format(e.json['name']))
        else:
            wiki_refresh = True
            logging.info('Forcing event refresh. Updating wiki: {}'.format(e.json['name']))

        """
        FIGURE OUT THE EVENT SOURCE
        """

        wiki_labels = wiki.get_labels()
        for tag in config['core']['event_sources']:
            if tag in wiki_labels:
                event_source = config['core']['event_sources'][tag]
                break

        """
        ADD ANY WHITELISTED INDICATORS FROM THE SUMMARY TABLE TO CRITS AND SIP
        """

        # Read the Indicator Summary table to see if there are any checked (whitelisted) indicators.
        good_indicators, whitelisted_indicators = wiki.read_indicator_summary_table()

        if whitelisted_indicators:

            logging.info('Detected newly whitelisted indicators: {}'.format(e.json['name']))

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
                                            logging.debug('Whitelisting "{}" indicator "{}" by association to: {}'.format(good_indicator['type'], rel, i['value']))
                                            whitelisted_indicators.append(good_indicator)

            if crits_api:

                # Add the whitelisted indicators to the CRITs whitelist.
                for i in whitelisted_indicators:

                    # If this is a "URI - Path" or "URI - URL" indicator, check its relationships to see if its
                    # corresponding "URI - Domain Name" or "Address - ipv4-addr" indicator was also checked. If it was,
                    # we want to ignore the path and URL indicators since the domain/IP serves as a least common denominator.
                    # This prevents the CRITs whitelist from ballooning in size and slowing things down over time.
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
                                            logging.debug('Ignoring redundant "{}" indicator "{}" for CRITs whitelist.'.format(i['type'], i['value']))
                                            skip = True

                    if not skip:
                        logging.warning('Adding "{}" indicator "{}" to CRITs whitelist.'.format(i['type'], i['value']))
    
                        try:
                            result = crits_api.add_indicator(i['value'], i['type'], source=config['intel']['default_source'],
                                                             reference=wiki.get_page_url(), bucket_list=['whitelist:e2w'],
                                                             add_domain=False)
    
                            # If the indicator was added successfully, update its status to Deprecated.
                            if result:
                                crits_api.status_update(result['id'], result['type'], 'Deprecated')
                        except:
                            logging.exception('Error adding "{}" indicator "{}" to CRITs whitelist'.format(i['type'], i['value']))

            if sip:

                # Add the whitelisted indicators to the SIP whitelist.
                for i in whitelisted_indicators:

                    # If this is a "URI - Path" or "URI - URL" indicator, check its relationships to see if its
                    # corresponding "URI - Domain Name" or "Address - ipv4-addr" indicator was also checked. If it was,
                    # we want to ignore the path and URL indicators since the domain/IP serves as a least common denominator.
                    # This prevents the SIP whitelist from ballooning in size and slowing things down over time.
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
                                            logging.debug('Ignoring redundant "{}" indicator "{}" for SIP whitelist.'.format(i['type'], i['value']))
                                            skip = True

                    if not skip:
                        logging.warning('Adding "{}" indicator "{}" to SIP whitelist.'.format(i['type'], i['value']))

                        try:
                            data = {'references': [{'source': event_source, 'reference': wiki.get_page_url()}],
                                    'status': 'Deprecated',
                                    'confidence': 'low',
                                    'impact': 'low',
                                    'tags': ['whitelist:e2w'],
                                    'type': i['type'],
                                    'username': 'eventsentry',
                                    'value': i['value']}
                            result = sip.post('indicators', data)
                        except ConflictError:
                            pass
                        except:
                            logging.exception('Error adding "{}" indicator "{}" to SIP whitelist'.format(i['type'], i['value']))

        """
        READ MANUAL INDICATORS FROM WIKI PAGE AND ADD NEW ONES TO CRITS
        """

        if crits_api and mongo_connection:

            # Read whatever manual indicators are listed on the wiki page so they can be added to CRITs and the event.
            manual_indicators = wiki.read_manual_indicators()

            for i in manual_indicators:

                # Add a "manual_indicator" tag to the indicators so that we can exclude them from the
                # monthly indicator pruning process.
                i['tags'].append('manual_indicator')

                # Get the indicator's CRITs status.
                crits_id = indicator.get_crits_id(mongo_connection, i)
                status = indicator.get_crits_status(mongo_connection, i)

                # Add it to CRITs if it doesn't already exist in CRITs and the status is New.
                if not crits_id and status == 'New':
                
                    try:
                        # Assemble the correct tags to add to this indicator.
                        ignore_these_tags = config['wiki']['ignore_these_tags']
                        add_these_tags = [tag for tag in e.json['tags'] if not tag in ignore_these_tags]
                        i['tags'] += add_these_tags

                        # Perform the API call to add the indicator.
                        result = crits_api.add_indicator(i['value'], i['type'], source=config['intel']['default_source'],
                                                         reference=wiki.get_page_url(), bucket_list=i['tags'],
                                                         add_domain=False)
                        logging.warning('Added "{}" manual indicator "{}" to CRITs: {}'.format(i['type'], i['value'], result['id']))
                    except:
                        logging.exception('Error adding "{}" manual indicator "{}" to CRITs'.format(i['type'], i['value']))

            # Check if there are any manual indicators in the event JSON that do not appear in this current
            # reading of the Manual Indicators section. This implies that someone removed something from the
            # table on the wiki page and refreshed the page. Presumably this means they did not actually want
            # that indicator, so the best we can do for now it to change its status to Informational.
            # TODO: Possible improvement to this would be to search for FA Queue ACE alerts for this indicator
            # and FP them, which would also set the indicator's status to Informational.
            old_manual_indicators = [i for i in e.json['indicators'] if 'manual_indicator' in i['tags']]
            for old_indicator in old_manual_indicators:
                if not [i for i in manual_indicators if i['type'] == old_indicator['type'] and i['value'] == old_indicator['value']]:
                    try:
                        # Find the indicator's CRITs ID and disable it.
                        crits_id = indicator.get_crits_id(mongo_connection, old_indicator)
                        if crits_id:
                            crits_api.status_update(crits_id, 'Indicator', 'Informational')
                            logging.error('Disabled deleted "{}" manual indicator "{}" in CRITs: {}'.format(old_indicator['type'], old_indicator['value'], crits_id))
                    except:
                        logging.exception('Error disabling deleted "{}" manual indicator "{}" in CRITs'.format(old_indicator['type'], old_indicator['value']))

        """
        READ MANUAL INDICATORS FROM WIKI PAGE AND ADD NEW ONES TO SIP
        """

        if sip:

            # Read whatever manual indicators are listed on the wiki page so they can be added to SIP and the event.
            manual_indicators = wiki.read_manual_indicators()

            for i in manual_indicators:

                # Add a "manual_indicator" tag to the indicators so that we can exclude them from the
                # monthly indicator pruning process.
                i['tags'].append('manual_indicator')

                # Try to add the indicator to SIP. A RequestError will be raised it it already exists.
                try:
                    # Assemble the correct tags to add to this indicator.
                    ignore_these_tags = config['wiki']['ignore_these_tags']
                    add_these_tags = [tag for tag in e.json['tags'] if not tag in ignore_these_tags]
                    i['tags'] += add_these_tags

                    # Perform the API call to add the indicator.
                    data = {'references': [{'source': event_source, 'reference': wiki.get_page_url()}],
                            'confidence': 'low',
                            'impact': 'low',
                            'tags': i['tags'],
                            'type': i['type'],
                            'username': 'eventsentry',
                            'value': i['value']}
                    try:
                        result = sip.post('indicators', data)
                    except ConflictError:
                        pass
                    except:
                        logging.exception('Error addding "{}" manual indicator "{}" to SIP: {}'.format(i['type'], i['value'], result['id']))
                    logging.warning('Added "{}" manual indicator "{}" to SIP: {}'.format(i['type'], i['value'], result['id']))
                except ConflictError:
                    # Since the indicator already exists, try to update it to make sure that it
                    # has all of the latest wiki page tags. Start by getting the existing indicator.
                    result = sip.get('/indicators?type={}&value={}'.format(i['type'], urllib.parse.quote(i['value'])))
                    if result:
                        try:
                            id_ = result[0]['id']
                            data = {'tags': i['tags']}
                            update_result = sip.put('/indicators/{}'.format(id_), data)
                        except ConflictError:
                            pass
                        except:
                            logging.exception('Error updating tags on manual indicator: {}'.format(id_))
                              
                        
                except:
                    logging.exception('Error adding "{}" manual indicator "{}" to SIP'.format(i['type'], i['value']))

            # Check if there are any manual indicators in the event JSON that do not appear in this current
            # reading of the Manual Indicators section. This implies that someone removed something from the
            # table on the wiki page and refreshed the page. Presumably this means they did not actually want
            # that indicator, so the best we can do for now it to change its status to Informational.
            # TODO: Possible improvement to this would be to search for FA Queue ACE alerts for this indicator
            # and FP them, which would also set the indicator's status to Informational.
            old_manual_indicators = [i for i in e.json['indicators'] if 'manual_indicator' in i['tags']]
            for old_indicator in old_manual_indicators:
                if not [i for i in manual_indicators if i['type'] == old_indicator['type'] and i['value'] == old_indicator['value']]:
                    try:
                        # Find the indicator's SIP ID and disable it.
                        result = sip.get('indicators?type={}&exact_value={}'.format(old_indicator['type'], urllib.parse.quote(old_indicator['value'])))
                        if result:
                            id_ = result[0]['id']
                            data = {'status': 'Informational'}
                            result = sip.put('indicators/{}'.format(id_), data)

                            logging.error('Disabled deleted "{}" manual indicator "{}" in SIP: {}'.format(old_indicator['type'], old_indicator['value'], id_))
                    except:
                        logging.exception('Error disabling deleted "{}" manual indicator "{}" in SIP'.format(old_indicator['type'], old_indicator['value']))

        """
        RE-SETUP THE EVENT
        """

        # Parse the event.
        try:
            e.setup(manual_indicators=manual_indicators, force=True)
        except:
            logging.exception('Error refreshing Event object: {}'.format(e.json['name']))
            return

        # Get the remediation status for the e-mails in the event.
        try:
            for email in e.json['emails']:
                email['remediated'] = False

                """
                key = ''
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
                """
        except:
            logging.exception('Error getting remediation status for e-mail.')
                        
        """
        ADD CRITs STATUS OF EACH INDICATOR TO THE EVENT JSON
        """

        """
        if crits_api and mongo_connection:

            # Used as a cache so we don't query CRITs for the same indicator.
            queried_indicators = {}

            # Query CRITs to get the status of the indicators.
            logging.debug('Querying CRITs for indicator statuses.') 

            for i in e.json['indicators']:
                type_value = '{}{}'.format(i['type'], i['value'])

                # Continue if we haven't already processed this type/value pair indicator.
                if not type_value in queried_indicators:

                    # Get the indicator status from CRITs. Ignore any indicators that were already set to Informational.
                    if not i['status'] == 'Informational':
                        i['status'] = indicator.get_crits_status(mongo_connection, i)

                    # Add the indicator to the queried cache.
                    queried_indicators[type_value] = i['status']
                # We've already queried CRITs for this type/value, so just set the status.
                else:
                    i['status'] = queried_indicators[type_value]
        """

        """
        ADD SIP STATUS OF EACH INDICATOR TO THE EVENT JSON
        """

        if sip:

            # Used as a cache so we don't query SIP for the same indicator.
            queried_indicators = {}

            # Query SIP to get the status of the indicators.
            logging.debug('Querying SIP for indicator statuses.')

            for i in e.json['indicators']:
                # Skip this indicator if it is whitelisted.
                if i['status'] == 'Whitelisted' or i['whitelisted']:
                    continue

                type_value = '{}{}'.format(i['type'], i['value'])

                # Continue if we haven't already processed this type/value pair indicator.
                if not type_value in queried_indicators:

                    # Get the indicator status from SIP. Ignore any indicators that were already set to Informational.
                    if not i['status'] == 'Informational':
                        result = sip.get('indicators?type={}&exact_value={}'.format(i['type'], urllib.parse.quote(i['value'])))
                        if result:
                            id_ = result[0]['id']
                            result = sip.get('indicators/{}'.format(id_))
                            i['status'] = result['status']

                    # Add the indicator to the queried cache.
                    queried_indicators[type_value] = i['status']
                # We've already queried SIP for this type/value, so just set the status.
                else:
                    i['status'] = queried_indicators[type_value]

        """
        RUN ALL OF THE CLEAN INDICATOR MODULES
        """

        e.clean_indicators()

        """
        RUN ALL OF THE EVENT DETECTION MODULES
        """

        # Save a copy of the old event tags to compare against to see if any were manually removed.
        old_tags = e.json['tags'][:]
        e.event_detections()

        """
        GATHER UP ALL OF THE EVENT TAGS
        """
     
        # Add the wiki tags to the event tags. This ensures that tags that we add to the wiki page
        # get added to the indicators in the Indicator Summary table.
        wiki_tags = wiki.get_labels()
        e.json['tags'] += wiki_tags
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

        # Now check if any of the wiki tags were manually removed. This can happen if we have an FP
        # event detection, so we want to make sure we don't keep applying those FP tags to the page.
        # NOTE: We only do this check if the event has NOT changed and the wiki refresh button was checked.
        if wiki_refresh:
            for tag in e.json['tags'][:]:
                if not tag in wiki_tags:
                    try:
                        e.json['tags'].remove(tag)
                        logging.info('Tag manually removed from wiki page: {}'.format(tag))
                    except:
                        pass

        """
        NOTIFY SLACK OF AN INCIDENT
        """

        if config['slack']['enabled']:
            if 'incidents' in e.json['tags'] and not e.json['slack_notify']:
                e.json['slack_notify'] = str(datetime.datetime.now())
                data = {'text': '<!channel> :rotating_light: Possible incident detected: {}'.format(e.json['wiki_url'])}
                try:
                    slack_webhook_url = config['slack']['slack_webhook_url']
                    proxy = config['network']['proxy']
                    if slack_webhook_url:
                        if proxy:
                            requests.post(config['slack']['slack_webhook_url'], json=data, proxies={'http': proxy, 'https': proxy})
                        else:
                            requests.post(config['slack']['slack_webhook_url'], json=data)
                except:
                    e.json['slack_notify'] = ''
                    logging.exception('Unable to notify Slack of incident')

        """
        UPDATE THE WIKI PAGE
        """

        # Refresh the wiki page using the updated JSON.
        try:
            wiki.refresh_event_page(e.json)
        except:
            logging.exception('Error refreshing wiki page: {}'.format(e.json['name']))

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
        logging.info('Processing the event intel: {}'.format(e.json['name']))

        # Figure out the event source.
        wiki_labels = wiki.get_labels()
        for tag in config['core']['event_sources']:
            if tag in wiki_labels:
                source = config['core']['event_sources'][tag]
                break

        # Add each good indicator into SIP.
        if sip:
            good_indicators, whitelisted_indicators = wiki.read_indicator_summary_table()
            for i in good_indicators:
                tags = sorted(list(set(i['tags'] + e.json['tags'])))
                ignore_these_tags = config['wiki']['ignore_these_tags']
                for label in ignore_these_tags:
                    try:
                        tags.remove(label)
                    except:
                        pass

                try:
                    data = {'references': [{'source': source, 'reference': wiki.get_page_url()}],
                            'status': i['status'],
                            'confidence': 'low',
                            'impact': 'low',
                            'tags': tags,
                            'type': i['type'],
                            'username': 'eventsentry',
                            'value': i['value']}
                    result = sip.post('indicators', data) 
                except ConflictError:
                    pass
                except:
                    logging.exception('Error when adding "{}" indicator "{}" into SIP.'.format(i['type'], i['value']))

        # Try to get the event description from the Overview section.
        overview_section = wiki.get_section('overview')
        try:
            description = overview_section.find('p').text.replace('"', '\\"')
        except:
            description = ''

        if source and description:
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
            giic_command = '{} --no-prompt -s "{}" -r "{}" -e "{}" --description "{}" --type "{}" --date "{}" --campaign "{}" --campaign-conf "{}" --bucket-list "{}"'.format(
                GETITINTOCRITS, source, wiki.get_page_url(), e.json['name'], description, event_type, event_time, campaign,
                campaign_conf, ','.join(sorted(list(set(e.json['tags'])))))
            commands.append(giic_command)

            # Command to craft the relationships between all the indicators and objects.
            br_command = '{} {}'.format(BUILD_RELATIONSHIPS, os.path.join(crits_root, 'relationships.txt'))
            commands.append(br_command)

            # Continue if we have the required pieces to run getitintocrits.py.
            if description and event_type and event_time and e.json['tags']:
                # Run all of the commands.
                command_string = ' && '.join(commands)
                os.system(command_string)

                # Query CRITs to make sure the event actually exists now.
                crits_events = [e['title'] for e in list(mongo_connection.find_all('events'))]
                if e.json['name'] in crits_events:

                    # If it exists in CRITs, close the event in ACE.
                    try:
                        ace_api.update_event_status(e.json['ace_event']['id'], 'CLOSED')
                        logging.warning('Closed event in ACE: {}'.format(e.json['name']))

                        # Update the wiki to reflect that the event was processed into CRITs.
                        wiki.update_event_processed()
                    except:
                        logging.exception('Error when closing the event in ACE: {}'.format(e.json['name']))

    logging.info('Finished event "{0:s}" in {1:.5f} seconds.'.format(event['name'], time.time() - start_time))


"""
#
# SENTRY FUNCTIONS
#
"""


def start(num_workers=1):
    """ Initializes a process pool and indefinitely queries ACE for open events to process. """

    # Make sure we don't create too many processes.
    if num_workers > os.cpu_count():
        num_workers = os.cpu_count()

    # Make sure we create at least one process.
    if num_workers < 1:
        num_workers = 1

    logging.info('Starting Event Sentry with {} workers.'.format(num_workers))

    while True:
        start_time = time.time()

        # Get the list of open events.
        open_events = get_open_events()

        # Get the valid campaigns from SIP.
        if sip:
            sip_campaign_names = [c['name'] for c in sip.get('campaigns')]
        else:
            sip_campaign_names = []

        # Create the process pool.
        pool = multiprocessing.Pool(processes=num_workers)

        # Build the list of argument tuples for starmap.
        argument_tuples = []
        for event in open_events:
            argument_tuples.append((event,sip_campaign_names))

        # Map the work queue (list of open events) into the pool.
        pool.starmap(process_event, argument_tuples)

        # Close the pool so no more tasks can be added to it.
        pool.close()

        # Wait for the worker processes to finish work
        pool.join()

        logging.info('Time taken = {0:.5f}'.format(time.time() - start_time))

        # Wait a little while before starting over.
        time.sleep(3)


if __name__ == '__main__':
    logging.info('Updating GeoIP database.')
    os.system('geoipupdate')
    try:
       start(num_workers=2)
    except:
        logging.exception('Caught an exception while running the sentry.')
        sys.exit(1)
